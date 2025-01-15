from typing import Optional

from ..guard.config import Guard
from ..models.scanresponse import Extraction
from ..utils.logger import get_default_logger
from .parser import ResponseParser
from .result import GuardMatch, ResponseMatch

logger = get_default_logger()

class ResponseEvaluator:
    """
    This ResponseEvaluator determines if conditions are met based on thresholds.
    """

    def __init__(self):
        self._parser = ResponseParser()  # Use the existing ResponseParser
        self._response = None

    def evaluate(
        self,
        response_extraction: Extraction,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """
        Evaluates a check condition using a Guard object.

        Args:
            response_extraction: The scan response extraction
            guard: The guard to eval with the response
            match_name: The match match for the guard

        Returns:
            GuardMatch with MATCH.YES if condition met, MATCH>NO if not met
        """
        try:
            result = self._parser.get_value(response_extraction, guard, match_name)
            # Handle different return types
            # PII and keyword
            match_count = None
            if isinstance(result, tuple) and len(result) == 3:  # (bool, float, int)
                exists, value, match_count = result
            # exploit, topic, classification, language
            elif isinstance(result, tuple) and len(result) == 2:  # (bool, float)
                exists, value = result
            # secrets and modality
            elif isinstance(result, bool):  # bool only
                exists, value = result, 1.0
            else:
                raise ValueError("Unexpected return type from get_value")

            if not exists:
                return GuardMatch(
                    response_match=ResponseMatch.NO,
                    guard_name=guard.name,
                    threshold=str(guard.threshold),
                    actual_value=value
                )
            # Use ThresholdHelper for comparison
            comparison_result = guard.threshold.compare(value)

            return GuardMatch(
                response_match=ResponseMatch.YES if comparison_result else ResponseMatch.NO,
                guard_name=guard.name,
                threshold=str(guard.threshold),
                actual_value=value,
                match_count=match_count if match_count else 0
            )
        except Exception as e:
            logger.debug("Error in check evaluation: %s", str(e))
            raise
