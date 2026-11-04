"""Domain error hierarchy. API layer maps these to HTTP status codes."""

from __future__ import annotations


class AicosError(Exception):
    code: str = "aicos_error"


class AuthenticationError(AicosError):
    code = "unauthenticated"


class AuthorizationError(AicosError):
    code = "forbidden"


class PolicyViolation(AuthorizationError):
    code = "policy_violation"


class ApprovalRequired(AicosError):
    code = "approval_required"

    def __init__(self, proposal_id: str, message: str = "Human approval required") -> None:
        super().__init__(message)
        self.proposal_id = proposal_id


class ApprovalError(AicosError):
    code = "approval_error"


class SecurityViolation(AicosError):
    code = "security_violation"


class RateLimited(AicosError):
    code = "rate_limited"


class NotFound(AicosError):
    code = "not_found"


class ValidationFailed(AicosError):
    code = "validation_failed"


class IntegrityError(AicosError):
    code = "integrity_error"


class PluginError(AicosError):
    code = "plugin_error"
