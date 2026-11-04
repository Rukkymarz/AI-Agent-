# GDPR / CCPA Data Subject Requests

1. **Verify identity** of the requester out-of-band. Log the request as a ticket (`ticket.create`).
2. **Access (Art. 15 / CCPA 1798.110):** export `memory_records` and `knowledge_documents` where `metadata->'pii'` is set and content matches the subject (email / id); include `tasks` initiated by the subject.
3. **Erasure (Art. 17 / CCPA 1798.105):** `user.delete` is a CRITICAL action → approval gateway (2 approvers). Execution deletes memory/knowledge rows and the Keycloak user. Audit rows are retained (legal obligation, Art. 17(3)(b)) but contain ids, not content.
4. **Retention:** `AICOS_DATA_RETENTION_DAYS` + short-term/conversation TTLs; the worker purges expired memory every 5 minutes.
5. Respond within 30 days (GDPR) / 45 days (CCPA). Attach the compliance report (`framework=GDPR`) as evidence.
