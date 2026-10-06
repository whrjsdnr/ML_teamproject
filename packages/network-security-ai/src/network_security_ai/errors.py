"""Typed failures at the standalone network inference boundary."""


class SecurityAIError(Exception):
    """Network module failure; callers decide how to report degraded operation."""


class SecurityAIInputValidationError(SecurityAIError):
    """Feature input does not meet the Top40 contract."""


class SecurityAIInferenceError(SecurityAIError):
    """Artifact loading or inference failed; never a benign fallback."""


class SecurityAIOutputValidationError(SecurityAIInferenceError):
    """Model probabilities do not satisfy the output contract."""
