"""Knowledge ingestion: load -> validate -> chunk -> scan -> embed -> index; plus retrieval.

Validation gates:
  * size + emptiness limits
  * content-hash dedupe per tenant
  * prompt-injection scan of every chunk (untrusted threshold) -> quarantined, never retrieved
  * PII flagging (email/phone/SSN/card) -> metadata for GDPR/CCPA handling
  * secret detection -> chunk redacted before indexing
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from aicos.domain.errors import ValidationFailed
from aicos.events.bus import DomainEvent, EventBus, EventType
from aicos.knowledge.chunking import chunk_text
from aicos.knowledge.loaders import Document, LoaderRegistry
from aicos.memory.service import MemoryService
from aicos.memory.store import MemoryRecord, MemoryScope, ScopeKey
from aicos.security.audit import AuditLog, Outcome
from aicos.security.firewall import PromptFirewall

_PII = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"(?<!\d)(\+?\d{1,2}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
}


def detect_pii(text: str) -> list[str]:
    return sorted(k for k, rx in _PII.items() if rx.search(text))


class IngestReport(BaseModel):
    source: str
    documents: int = 0
    chunks: int = 0
    quarantined: int = 0
    redacted_secrets: int = 0
    duplicates: int = 0
    pii: list[str] = Field(default_factory=list)


class RetrievedChunk(BaseModel):
    source: str
    score: float
    text: str  # already wrapped as untrusted content
    metadata: dict[str, object] = Field(default_factory=dict)


class KnowledgeService:
    def __init__(
        self,
        memory: MemoryService,
        firewall: PromptFirewall,
        audit: AuditLog,
        bus: EventBus,
        loaders: LoaderRegistry | None = None,
        *,
        max_bytes: int = 25_000_000,
        chunk_size: int = 1200,
        chunk_overlap: int = 150,
    ) -> None:
        self.memory, self.firewall, self.audit, self.bus = memory, firewall, audit, bus
        self.loaders = loaders or LoaderRegistry()
        self.max_bytes, self.chunk_size, self.chunk_overlap = max_bytes, chunk_size, chunk_overlap
        self._hashes: dict[str, set[str]] = {}

    async def ingest_bytes(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        source: str,
        data: bytes,
        scope: MemoryScope = MemoryScope.COMPANY,
        owner_id: str = "company",
    ) -> IngestReport:
        if not data:
            raise ValidationFailed("empty document")
        if len(data) > self.max_bytes:
            raise ValidationFailed("document too large")
        return await self.ingest_documents(
            tenant_id=tenant_id,
            actor_id=actor_id,
            source=source,
            docs=self.loaders.load(data, source),
            scope=scope,
            owner_id=owner_id,
        )

    async def ingest_documents(
        self,
        *,
        tenant_id: str,
        actor_id: str,
        source: str,
        docs: list[Document],
        scope: MemoryScope = MemoryScope.COMPANY,
        owner_id: str = "company",
    ) -> IngestReport:
        report = IngestReport(source=source)
        seen = self._hashes.setdefault(tenant_id, set())
        records: list[MemoryRecord] = []
        pii: set[str] = set()
        for doc in docs:
            if not doc.text.strip():
                continue
            if doc.content_hash in seen:
                report.duplicates += 1
                continue
            seen.add(doc.content_hash)
            report.documents += 1
            for ch in chunk_text(doc.text, size=self.chunk_size, overlap=self.chunk_overlap):
                text, n_secrets = self.firewall.redact_secrets(ch.text)
                report.redacted_secrets += n_secrets
                scan = self.firewall.scan(text, untrusted=True)
                flags = detect_pii(text)
                pii.update(flags)
                if not scan.allowed:
                    report.quarantined += 1
                records.append(
                    MemoryRecord(
                        tenant_id=tenant_id,
                        scope=scope,
                        owner_id=owner_id,
                        content=text,
                        metadata={
                            "source": doc.source,
                            "document_id": doc.id,
                            "chunk": ch.index,
                            "heading": ch.heading,
                            "mime": doc.mime,
                            "content_hash": doc.content_hash,
                            "pii": flags,
                            "quarantined": not scan.allowed,
                            "threats": sorted(scan.threats) if not scan.allowed else [],
                            **{k: v for k, v in doc.metadata.items() if isinstance(v, (str, int, float, bool))},
                        },
                    )
                )
        if records:
            await self.memory.remember_many(records)
        report.chunks, report.pii = len(records), sorted(pii)
        self.audit.record(
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_type="human",
            action="knowledge.ingest",
            resource=source,
            outcome=Outcome.SUCCESS,
            details=report.model_dump(),
        )
        await self.bus.publish(
            DomainEvent(type=EventType.KNOWLEDGE_INGESTED, tenant_id=tenant_id, source="knowledge", payload=report.model_dump())
        )
        if report.quarantined:
            await self.bus.publish(
                DomainEvent(
                    type=EventType.SECURITY_ALERT,
                    tenant_id=tenant_id,
                    source="knowledge",
                    payload={"kind": "indirect_prompt_injection", "source": source, "chunks": report.quarantined},
                )
            )
        return report

    async def search(
        self,
        *,
        tenant_id: str,
        query: str,
        keys: list[ScopeKey] | None = None,
        k: int = 6,
    ) -> list[RetrievedChunk]:
        keys = keys or [ScopeKey(scope=MemoryScope.COMPANY, owner_id="company")]
        hits = await self.memory.recall(tenant_id=tenant_id, query=query, keys=keys, k=k)
        return [
            RetrievedChunk(
                source=str(h.record.metadata.get("source", "unknown")),
                score=round(h.score, 4),
                text=self.firewall.wrap_untrusted(h.record.content, source=str(h.record.metadata.get("source", "memory"))),
                metadata={"scope": h.record.scope, "pii": h.record.metadata.get("pii", [])},
            )
            for h in hits
        ]
