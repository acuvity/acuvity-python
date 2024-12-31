from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..constants import Verdict


@dataclass
class CheckResult:
    """Result of a single check operation."""
    verdict: Verdict
    check_name: str
    threshold: float
    actual_value: float
    details: Optional[Dict[str, Any]] = None

@dataclass
class ProcessorResult:
    """Result of processing multiple checks or a configuration."""
    verdict: Verdict
    failed_checks: list[CheckResult]
    total_checks: int
    details: Optional[Dict[str, Any]] = None
