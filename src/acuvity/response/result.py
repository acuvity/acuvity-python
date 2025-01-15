from dataclasses import dataclass
from enum import Enum

from acuvity.guard.constants import GuardName


class ResponseMatch(str, Enum):
    """Enumeration for check matches."""
    YES = "YES"
    NO = "NO"

@dataclass
class GuardMatch:
    """Result of a single check operation."""
    response_match: ResponseMatch
    guard_name: GuardName
    actual_value: float
    threshold: str
    match_count: int = 0

@dataclass
class Matches:
    """Result of processing multiple checks or a configuration."""
    input_data: str
    response_match: ResponseMatch
    matched_checks: list[GuardMatch]
    all_checks: list[GuardMatch]
