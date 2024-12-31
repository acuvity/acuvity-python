class VerdictProcessingError(Exception):
    """Base exception for response processing errors."""

class ConfigurationError(VerdictProcessingError):
    """Raised when there's an error in the configuration."""

class ValidationError(VerdictProcessingError):
    """Raised when validation fails."""
