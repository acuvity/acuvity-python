from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from acuvity.guard.constants import GuardName
from acuvity.guard.threshold import Threshold


class ResponseMatch(str, Enum):
    """Enumeration for check verdicts."""
    YES = "YES"
    NO = "NO"

@dataclass
class GuardMatch:
    """Result of a single check operation."""
    response_match: ResponseMatch
    guard_name: GuardName
    actual_value: float
    threshold: str

@dataclass
class Matches:
    """Result of processing multiple checks or a configuration."""
    response_match: ResponseMatch
    matched_checks: list[GuardMatch]
    all_checks: list[GuardMatch]
