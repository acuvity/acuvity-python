class VerdictProcessingError(Exception):
    """Base exception for response processing errors."""
    pass

class ConfigurationError(VerdictProcessingError):
    """Raised when there's an error in the configuration."""
    pass

class ValidationError(VerdictProcessingError):
    """Raised when validation fails."""
    pass
