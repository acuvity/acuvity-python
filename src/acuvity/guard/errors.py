class ValidationError(Exception):
    """Raised when validation fails."""

class GuardConfigError(Exception):
    """Base exception for guard parser errors"""

class ConfigValidationError(GuardConfigError):
    """Raised when config validation fails"""

class ThresholdParsingError(GuardConfigError):
    """Raised when threshold parsing fails"""
