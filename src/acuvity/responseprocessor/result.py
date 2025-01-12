from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..guard.constants import GuardName
from .constants import Verdict


@dataclass
class GuardVerdict:
    """Result of a single check operation."""
    verdict: Verdict
    guard_name: GuardName
    threshold: float
    actual_value: float
    details: Optional[Dict[str, Any]] = None

@dataclass
class OverallVerdicts:
    """Result of processing multiple checks or a configuration."""
    verdict: Verdict
    failed_checks: list[GuardVerdict]
    total_checks: int
    details: Optional[Dict[str, Any]] = None
