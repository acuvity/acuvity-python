from abc import ABC, abstractmethod
from typing import Any, Dict

from ..models import GuardResult


class GuardEvaluator(ABC):
    """Abstract base class for guard evaluators."""

    @abstractmethod
    def evaluate(self, response_data: Dict[str, Any], guard_config: Dict[str, Any]) -> GuardResult:
        """Evaluate the guard against response data."""
        pass
