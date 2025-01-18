from enum import Enum
from typing import List, Optional


class ComparisonOperator(Enum):
    """Valid comparison operators for thresholds"""
    GREATER_THAN = '>'
    GREATER_EQUAL = '>='
    EQUAL = '=='
    LESS_EQUAL = '<='
    LESS_THAN = '<'

class GuardName(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    MALICIOUS_URL = "malicious_url"
    TOXIC = "toxic"
    BIASED = "biased"
    HARMFUL = "harmful"
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
    def values(cls) -> List[str]:
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
