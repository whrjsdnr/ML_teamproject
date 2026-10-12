"""Failures never become a NORMAL prediction."""


class DNSSecurityAIError(Exception):
    """DNS inference boundary failure."""


class DNSInputError(DNSSecurityAIError):
    """Input violates the stateless nine-feature contract."""


class DNSArtifactError(DNSSecurityAIError):
    """Missing, corrupt, incompatible or untrusted artifact."""


class DNSInferenceError(DNSSecurityAIError):
    """Missing runtime or failed model execution."""


class DNSOutputError(DNSInferenceError):
    """Output violates binary probability semantics."""
