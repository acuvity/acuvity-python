from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


class Verdict(str, Enum):
    """Enumeration for possible verdicts."""
    PASS = "PASS"
    FAIL = "FAIL"

@dataclass
class GuardResult:
    """Dataclass to store the result of a guard evaluation."""
    verdict: Verdict
    guard_name: str
    details: Dict[str, Any]
    threshold: float
    actual_value: float
