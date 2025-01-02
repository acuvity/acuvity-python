from typing import Any, Dict

from ..constants import ThresholdOperator
from ..models.result import CheckResult
from ..util.path_resolver import PathResolver
from .evaluator import CheckEvaluator


class CheckBuilder:
    """
    Provides a fluent interface for building checks.
    """

    def __init__(self, evaluator: CheckEvaluator, response: Dict[str, Any], guard_name: str):
        self._evaluator = evaluator
        self._response = response
        self._guard_name = guard_name
        self._path_resolver = PathResolver()
        self._match_name = None

    def for_match(self, match_name: str) -> 'CheckBuilder':
        """
        Specify a match name for match-based guards.
        Returns self for method chaining.
        """
        self._match_name = match_name
        return self

    def _get_check_path(self) -> str:
        """Get the resolved path for the check."""
        match_name = getattr(self, '_match_name', None)
        return self._path_resolver.get_path(self._guard_name, match_name)

    def threshold_greater_than(self, threshold: float) -> CheckResult:
        """Check if value is greater than threshold."""
        path = self._get_check_path()
        return self._evaluator.evaluate(
            self._response,
            path,
            threshold,
            ThresholdOperator.GREATER_THAN
        )

    def threshold_less_than(self, threshold: float) -> CheckResult:
        """Check if value is less than threshold."""
        path = self._get_check_path()
        return self._evaluator.evaluate(
            self._response,
            path,
            threshold,
            ThresholdOperator.LESS_THAN
        )

    def equals(self, value: float) -> CheckResult:
        """Check if value equals the specified value."""
        path = self._get_check_path()
        return self._evaluator.evaluate(
            self._response,
            path,
            value,
            ThresholdOperator.EQUAL
        )
