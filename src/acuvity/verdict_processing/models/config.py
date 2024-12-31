from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class GuardConfig:
    """Configuration for a single guard."""
    guard_name: str
    threshold: float
    action: str
    matches: Optional[Dict[str, Any]] = None

@dataclass
class ProcessorConfig:
    """Overall configuration for response processing."""
    guards: List[GuardConfig]
    metadata: Optional[Dict[str, Any]] = None
