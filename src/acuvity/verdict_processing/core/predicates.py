from typing import Any, Callable, Dict

from ..constants import ThresholdOperator
from ..models.result import CheckResult


class Predicate:
    """Class representing a check predicate."""

    def __init__(self, path: str, threshold: float, operator: ThresholdOperator):
        self.path = path
        self.threshold = threshold
        self.operator = operator

class Predicates:
    """Factory for common check predicates."""

    @staticmethod
    def prompt_injection_exceeds(threshold: float) -> Predicate:
        """Create a predicate for prompt injection check."""
        return Predicate("exploits.prompt_injection", threshold, ThresholdOperator.GREATER_THAN)

    @staticmethod
    def toxicity_exceeds(threshold: float) -> Predicate:
        """Create a predicate for toxicity check."""
        return Predicate("exploits.toxicity", threshold, ThresholdOperator.GREATER_THAN)

    @staticmethod
    def bias_below(threshold: float) -> Predicate:
        """Create a predicate for bias check."""
        return Predicate("exploits.bias", threshold, ThresholdOperator.LESS_THAN)
