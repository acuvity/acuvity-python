# src/acuvity/verdict_processing/evaluators/evaluator.py
from typing import Any, Dict, Union

from ...utils.logger import get_default_logger
from ..constants import ThresholdOperator, Verdict
from ..models.result import CheckResult
from ..util.response_parser import ResponseParser
from ..util.threshold_helper import ThresholdHelper

logger = get_default_logger()

class CheckEvaluator:
    """
    Handles pure check evaluation without considering actions.
    This evaluator determines if conditions are met based on thresholds.
    """

    def __init__(self, parser: ResponseParser, threshold_helper: ThresholdHelper):
        self._parser = parser
        self._threshold_helper = threshold_helper

    def evaluate(
        self,
        response: Dict[str, Any],
        path: str,
        threshold: Union[float, str],
        operator: ThresholdOperator
    ) -> CheckResult:
        """
        Evaluates a check condition.

        Args:
            response: The response data to check
            path: Path to the value in the response
            threshold: Threshold value or threshold string with operator
            operator: Operator to use for comparison

        Returns:
            CheckResult with PASS if condition met, FAIL if not met
        """
        try:
            value = self._parser.get_value(response, path)

            if isinstance(threshold, (int, float)):
                threshold_value = float(threshold)
            else:
                threshold_value, parsed_operator = self._threshold_helper.parse_threshold(threshold)
                operator = parsed_operator

            comparison_result = self._threshold_helper.compare(value, threshold_value, operator)

            return CheckResult(
                verdict=Verdict.PASS if comparison_result else Verdict.FAIL,
                check_name=path,
                threshold=threshold_value,
                actual_value=float(value),
                details={
                    'operator': operator,
                    'condition_met': comparison_result
                }
            )
        except Exception as e:
            logger.debug("Error in check evaluation: %s",{str(e)})
            raise e
