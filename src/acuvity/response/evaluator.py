from typing import Optional

from ..guard.config import Guard
from ..models.scanresponse import Scanresponse
from ..utils.logger import get_default_logger
from .parser import ResponseParser
from .result import GuardVerdict, Verdict

logger = get_default_logger()

class ResponseEvaluator:
    """
    Handles pure check evaluation without considering actions.
    This evaluator determines if conditions are met based on thresholds.
    """

    def __init__(self):
        self._parser = ResponseParser()  # Use the existing ResponseParser
        self._response = None

    def evaluate(
        self,
        response: Scanresponse,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> GuardVerdict:
        """
        Evaluates a check condition using a Threshold object.

        Args:
            response: The response data to check
            path: Path to the value in the response
            threshold: Threshold object containing value and operator

        Returns:
            GuardVerdict with PASS if condition met, FAIL if not met
        """
        try:
            if not response.extractions:
                raise ValueError("No extractions found in the response")
            extraction = response.extractions[0]
            result = self._parser.get_value(extraction, guard.name, match_name)
            # Handle different return types
            # PII and keyword
            if isinstance(result, tuple) and len(result) == 3:  # (bool, float, int)
                exists, value, _ = result
            # exploit, topic, classification, language
            elif isinstance(result, tuple) and len(result) == 2:  # (bool, float)
                exists, value = result
            # secrets and modality
            elif isinstance(result, bool):  # bool only
                exists, value = result, 1.0
            else:
                raise ValueError("Unexpected return type from get_value")

            if not exists:
                return GuardVerdict(
                    verdict=Verdict.PASS,
                    guard_name=guard.name,
                    threshold=guard.threshold.value,
                    actual_value=value,
                    details={
                        'operator': guard.threshold.operator.value,
                        'condition_met': True,
                        'reason': 'Guard not found in response'
                    }
                )
            # Use ThresholdHelper for comparison
            comparison_result = guard.threshold.compare(value)

            return GuardVerdict(
                verdict=Verdict.FAIL if comparison_result else Verdict.PASS,
                guard_name=guard.name,
                threshold=guard.threshold.value,
                actual_value=value,
                details={
                    'operator': guard.threshold.operator.value,
                    'condition_met': comparison_result
                }
            )
        except Exception as e:
            logger.debug("Error in check evaluation: %s", str(e))
            raise
