from typing import Any, Dict

from acuvity.models.scanresponse import Scanresponse

from ..constants import ComparisonOperator
from ..models.result import CheckResult
from ..util.threshold_helper import Threshold
from .guard_processor import CheckEvaluator


class GuardCheck:
    """
    Represents a guard check, allowing for threshold evaluations with method chaining.
    """

    def __init__(self, evaluator: CheckEvaluator, response: Scanresponse, guard_name: str):
        self._evaluator = evaluator
        self._response = response  # Pass the full Scanresponse object
        self._guard_name = guard_name
        self._match_name = None  # Default to no match name

    def for_match(self, match_name: str) -> "GuardCheck":
        """
        Specify a match name for match-based guards.
        Returns self for method chaining.
        """
        self._match_name = match_name
        return self

    def _get_check_details(self) -> Dict[str, Any]:
        """
        Prepare details for evaluation, including the guard name and match name.
        """
        return {
            "guard_name": self._guard_name,
            "match_name": self._match_name,
        }

    def threshold_greater_than(self, val: float) -> CheckResult:
        """
        Check if the guard value is greater than the specified threshold.
        """
        details = self._get_check_details()
        threshold = Threshold(val, ComparisonOperator.GREATER_THAN)
        return self._evaluator.evaluate(
            self._response,
            details["guard_name"],
            threshold,
            details["match_name"]
        )

    def threshold_greater_equal(self, val: float) -> CheckResult:
        """
        Check if the guard value is greater than or equal to the specified threshold.
        """
        details = self._get_check_details()
        threshold = Threshold(val, ComparisonOperator.GREATER_EQUAL)
        return self._evaluator.evaluate(
            self._response,
            details["guard_name"],
            threshold,
            details["match_name"]
        )

    def threshold_less_than(self, val: float) -> CheckResult:
        """
        Check if the guard value is less than the specified threshold.
        """
        details = self._get_check_details()
        threshold = Threshold(val, ComparisonOperator.LESS_THAN)
        return self._evaluator.evaluate(
            self._response,
            details["guard_name"],
            threshold,
            details["match_name"]
        )

    def threshold_less_equal(self, val: float) -> CheckResult:
        """
        Check if the guard value is less than or equal to the specified threshold.
        """
        details = self._get_check_details()
        threshold = Threshold(val, ComparisonOperator.LESS_EQUAL)
        return self._evaluator.evaluate(
            self._response,
            details["guard_name"],
            threshold,
            details["match_name"]
        )

    def equals(self, val: float) -> CheckResult:
        """
        Check if the guard value equals the specified value.
        """
        details = self._get_check_details()
        threshold = Threshold(val, ComparisonOperator.EQUAL)
        return self._evaluator.evaluate(
            self._response,
            details["guard_name"],
            threshold,
            details["match_name"]
        )
