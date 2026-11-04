"""aicos-worker: background duties that must never run inside request handlers.

* event consumers (Redis Streams consumer groups) -> n8n webhooks (HMAC-signed)
* memory TTL purge
* audit chain verification + head-hash anchoring (tamper evidence outside the DB)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path

import httpx

from aicos.container import build_container
from aicos.events.bus import DomainEvent, EventType
from aicos.security.signing import RequestSigner

log = logging.getLogger("aicos.worker")
FORWARD = {
    EventType.APPROVAL_REQUESTED,
    EventType.APPROVAL_GRANTED,
    EventType.ACTION_EXECUTED,
    EventType.SECURITY_ALERT,
    EventType.LEAD_FOUND,
    EventType.TICKET_CREATED,
    EventType.DEPLOYMENT_COMPLETED,
}


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(line)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}')
    c = build_container()
    n8n_url = os.environ.get("AICOS_N8N_WEBHOOK_URL", "http://n8n:5678/webhook/aicos-approval")
    key = c.secrets.get("n8n_signing_key") or ""
    signer = RequestSigner("aicos", key.encode()) if len(key) >= 32 else None
    http = httpx.AsyncClient(timeout=10)

    async def forward(evt: DomainEvent) -> None:
        if signer is None:
            return
        body = json.dumps({"type": evt.type, "payload": evt.payload, "id": evt.id, "tenant": evt.tenant_id}).encode()
        headers = {**signer.sign("POST", httpx.URL(n8n_url).path, body), "Content-Type": "application/json"}
        r = await http.post(n8n_url, content=body, headers=headers)
        r.raise_for_status()

    for t in FORWARD:
        c.bus.subscribe(t, forward, name=f"n8n-forward-{t}")

    async def housekeeping() -> None:
        anchor = Path(os.environ.get("AICOS_AUDIT_ANCHOR_FILE", "/var/lib/aicos/audit-anchor.jsonl"))
        while True:
            purged = await c.memory.purge_expired()
            v = c.audit.verify()
            if not v.valid:
                log.critical("AUDIT CHAIN INVALID at seq=%s reason=%s", v.first_invalid_seq, v.reason)
            line = json.dumps({"head": v.head_hash, "records": v.records_checked, "valid": v.valid}) + "\n"
            await asyncio.to_thread(_append, anchor, line)  # ship to WORM storage (S3 Object Lock) via backup job
            log.info("housekeeping purged=%d audit_valid=%s records=%d", purged, v.valid, v.records_checked)
            await asyncio.sleep(300)

    runners = [housekeeping()]
    if hasattr(c.bus, "run"):
        runners.append(c.bus.run())  # type: ignore[attr-defined]
    await asyncio.gather(*runners)


if __name__ == "__main__":
    asyncio.run(main())
