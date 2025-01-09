class VerdictProcessingError(Exception):
    """Base exception for response processing errors."""

class ConfigurationError(VerdictProcessingError):
    """Raised when there's an error in the configuration."""

class ValidationError(VerdictProcessingError):
    """Raised when validation fails."""

class GuardParserError(Exception):
    """Base exception for guard parser errors"""

class ConfigValidationError(GuardParserError):
    """Raised when config validation fails"""

class ThresholdParsingError(GuardParserError):
    """Raised when threshold parsing fails"""
