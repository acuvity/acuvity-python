from enum import Enum
from typing import Optional


class ComparisonOperator(Enum):
    """Valid comparison operators for thresholds"""
    GREATER_THAN = '>'
    GREATER_EQUAL = '>='
    EQUAL = '=='
    LESS_EQUAL = '<='
    LESS_THAN = '<'

class GuardName(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAIL_BREAK = "jail_break"
    MALICIOUS_URL = "malicious_url"
    TOXICITY = "toxicity"
    BIAS = "bias"
    HARMFUL_CONTENT = "harmful"
    LANGUAGE = "language"
    MODALITY = "modality"
    PII_DETECTOR = "pii_detector"
    SECRETS_DETECTOR = "secrets_detector"
    KEYWORD_DETECTOR = "keyword_detector"

    def __str__(self) -> str:
        """
        Return the string representation of the enum member (i.e., its value).
        """
        return self.value

    @classmethod
    def values(cls) -> list[str]:
        return [member.value for member in cls]

    @classmethod
    def valid(cls, guard: str) -> bool:
        """
        Check if the input string represents a valid guard name.

        Args:
            input: Input string to check.

        Returns:
            bool: True if the input matches a guard name, otherwise False.
        """
        # Check against GuardName enum values
        if guard in {guard.value for guard in GuardName}:
            return True
        return False

    @classmethod
    def get(cls, name: str) -> Optional['GuardName']:
        try:
            return cls(name.lower())
        except ValueError:
            return None
