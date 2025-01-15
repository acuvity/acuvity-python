class ValidationError(Exception):
    """Raised when validation fails."""

class GuardConfigError(Exception):
    """Base exception for guard parser errors"""

class GuardConfigValidationError(GuardConfigError):
    """Raised when config validation fails"""

class GuardThresholdParsingError(GuardConfigError):
    """Raised when threshold parsing fails"""
