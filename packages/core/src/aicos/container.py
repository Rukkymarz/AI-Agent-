"""Composition root (dependency injection). The ONLY place that knows concrete adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aicos.agents.registry import AgentRegistry
from aicos.approvals.gateway import ApprovalGateway, InMemoryProposalRepository, ProposalRepository
from aicos.config import Settings
from aicos.events.bus import EventBus, InMemoryEventBus
from aicos.knowledge.loaders import LoaderRegistry
from aicos.knowledge.pipeline import KnowledgeService
from aicos.llm.providers import EchoProvider, LLMProvider
from aicos.llm.router import LLMRouter, TaskType
from aicos.memory.embeddings import Embedder, HashingEmbedder
from aicos.memory.service import MemoryService
from aicos.memory.store import InMemoryVectorStore, VectorStore
from aicos.observability.metrics import Metrics, NoopMetrics, PrometheusMetrics
from aicos.orchestrator.actions import ActionExecutor
from aicos.orchestrator.graph import Orchestrator
from aicos.plugins.manager import HostServices, PluginManager
from aicos.plugins.signing import TrustStore
from aicos.security.audit import AuditLog, AuditStore, InMemoryAuditStore
from aicos.security.firewall import PromptFirewall
from aicos.security.policy import PolicyEngine
from aicos.security.ratelimit import TokenBucketLimiter
from aicos.security.secrets import ChainedSecretProvider, DockerSecretProvider, EnvSecretProvider, SecretProvider
from aicos.security.signing import RequestVerifier


@dataclass
class Container:
    settings: Settings
    audit: AuditLog
    bus: EventBus
    policy: PolicyEngine
    firewall: PromptFirewall
    approvals: ApprovalGateway
    router: LLMRouter
    memory: MemoryService
    knowledge: KnowledgeService
    agents: AgentRegistry
    executor: ActionExecutor
    orchestrator: Orchestrator
    plugins: PluginManager
    secrets: SecretProvider
    metrics: Metrics
    rate_limiter: TokenBucketLimiter
    request_verifier: RequestVerifier | None


def _metrics() -> Metrics:
    try:
        return PrometheusMetrics()
    except ImportError:  # pragma: no cover
        return NoopMetrics()


def build_container(settings: Settings | None = None, **overrides: Any) -> Container:
    s = settings or Settings()
    root = Path(overrides.pop("root", Path.cwd()))

    # --- infrastructure adapters (selected by config; overridable for tests) ---
    audit_store: AuditStore = overrides.get("audit_store") or InMemoryAuditStore()
    proposals: ProposalRepository = overrides.get("proposal_repo") or InMemoryProposalRepository()
    vector_store: VectorStore = overrides.get("vector_store") or InMemoryVectorStore()
    bus: EventBus = overrides.get("bus") or InMemoryEventBus()
    if s.database_url and not overrides.get("audit_store"):  # pragma: no cover - needs postgres
        from aicos.infrastructure.postgres import PgAuditStore, PgProposalRepository, PgVectorStore, connect_pool

        pool = connect_pool(s.database_url.get_secret_value())
        audit_store, proposals, vector_store = PgAuditStore(pool), PgProposalRepository(pool), PgVectorStore(pool, s.embedding_dim)
    if s.redis_url and not overrides.get("bus"):  # pragma: no cover - needs redis
        from aicos.infrastructure.redis_bus import RedisStreamsEventBus

        bus = RedisStreamsEventBus(s.redis_url)

    secrets_chain: list[SecretProvider] = []
    if s.vault_addr:  # pragma: no cover - needs vault
        from aicos.infrastructure.vault import VaultSecretProvider

        secrets_chain.append(VaultSecretProvider.from_approle(s.vault_addr, s.vault_role_id or "", s.vault_secret_id_file))
    secrets_chain += [DockerSecretProvider(), EnvSecretProvider()]
    secrets: SecretProvider = overrides.get("secrets") or ChainedSecretProvider(*secrets_chain)

    providers: dict[str, LLMProvider] = overrides.get("providers") or {}
    embedder: Embedder | None = overrides.get("embedder")
    if not providers:
        if s.llm_provider == "echo":
            providers = {"ollama": EchoProvider()}  # echo impersonates the default provider name
        else:  # pragma: no cover - needs ollama
            from aicos.infrastructure.ollama import OllamaProvider

            providers = {"ollama": OllamaProvider(s.ollama_url)}
    if embedder is None:
        if s.embedding_provider == "hashing":
            embedder = HashingEmbedder(dim=s.embedding_dim)
        else:  # pragma: no cover
            from aicos.infrastructure.ollama import OllamaEmbedder

            embedder = OllamaEmbedder(s.ollama_url, s.embedding_model, s.embedding_dim)

    # --- core services ---
    metrics = overrides.get("metrics") or _metrics()
    audit = AuditLog(audit_store, s.key("audit_hmac_key"))
    policy_path = root / s.policy_file if s.policy_file else None
    policy = PolicyEngine.from_yaml(policy_path) if policy_path and policy_path.exists() else PolicyEngine()
    firewall = PromptFirewall()
    approvals = ApprovalGateway(proposals, audit, bus, s.key("approval_signing_key"))

    def usage(task: TaskType, resp: Any, model: str, err: Exception | None) -> None:
        if resp is not None:
            metrics.llm(model, task, True, resp.input_tokens, resp.output_tokens, resp.cost_usd, resp.latency_ms / 1000)
        else:
            metrics.llm(model, task, False, 0, 0, 0.0, 0.0)

    models_path = root / s.models_file if s.models_file else None
    router = (
        LLMRouter.from_yaml(models_path, providers, usage_hook=usage)
        if models_path and models_path.exists()
        else LLMRouter(providers, usage_hook=usage)
    )
    memory = MemoryService(vector_store, embedder)
    loaders = LoaderRegistry()
    knowledge = KnowledgeService(memory, firewall, audit, bus, loaders)
    agents = AgentRegistry(router)
    catalog = root / s.agent_catalog_dir
    if catalog.exists():
        agents.load_catalog(catalog)
    executor = ActionExecutor(bus)
    orchestrator = Orchestrator(
        agents=agents,
        policy=policy,
        approvals=approvals,
        audit=audit,
        bus=bus,
        firewall=firewall,
        memory=memory,
        knowledge=knowledge,
        executor=executor,
        metrics=metrics,
    )
    host = HostServices(
        agents=agents,
        executor=executor,
        router=router,
        bus=bus,
        memory=memory,
        secrets=secrets,
        audit=audit,
        approvals=approvals,
        policy=policy,
        loaders=loaders,
    )
    trust = overrides.get("trust_store") or (TrustStore.from_directory(root / s.trusted_keys_dir) if s.trusted_keys_dir else TrustStore())
    plugins = PluginManager(host, trust, tenant_id=s.tenant_id)
    if s.plugin_dir and (root / s.plugin_dir).is_dir():
        plugins.discover(root / s.plugin_dir)  # discovery only; verify/install/activate stay explicit + approved
    verifier = (
        RequestVerifier({k: v.get_secret_value().encode() for k, v in s.service_signing_keys.items()}) if s.service_signing_keys else None
    )
    return Container(
        settings=s,
        audit=audit,
        bus=bus,
        policy=policy,
        firewall=firewall,
        approvals=approvals,
        router=router,
        memory=memory,
        knowledge=knowledge,
        agents=agents,
        executor=executor,
        orchestrator=orchestrator,
        plugins=plugins,
        secrets=secrets,
        metrics=metrics,
        rate_limiter=TokenBucketLimiter(s.rate_limit_capacity, s.rate_limit_refill_per_s),
        request_verifier=verifier,
    )
