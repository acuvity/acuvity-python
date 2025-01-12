from pathlib import Path
from typing import Dict, List, Optional, Union

from ...models.scanresponse import Scanresponse
from ...utils.logger import get_default_logger
from ..constants import (
    ComparisonOperator,
    Verdict,
    analyzer_id_name_map,
)
from ..models.errors import ConfigurationError
from ...config.guard_config import Guard, GuardConfig
from ..models.result import CheckResult, ProcessorResult
from ..util.response_parser import ResponseParser
from ..util.threshold_helper import Threshold, ThresholdHelper

logger = get_default_logger()

class CheckEvaluator:
    """
    Handles pure check evaluation without considering actions.
    This evaluator determines if conditions are met based on thresholds.
    """

    def __init__(self):
        self._parser = ResponseParser()  # Use the existing ResponseParser
        self._threshold_helper = ThresholdHelper()
        self._response = None

    def evaluate(
        self,
        response: Scanresponse,
        guard_name: str,
        threshold: Threshold,
        match_name: Optional[str] = None
    ) -> CheckResult:
        """
        Evaluates a check condition using a Threshold object.

        Args:
            response: The response data to check
            path: Path to the value in the response
            threshold: Threshold object containing value and operator

        Returns:
            CheckResult with PASS if condition met, FAIL if not met
        """
        try:
            if not response.extractions:
                raise ValueError("No extractions found in the response")
            extraction = response.extractions[0]
            result = self._parser.get_value(extraction, guard_name, match_name)
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
                return CheckResult(
                    verdict=Verdict.PASS,
                    guard_name=guard_name,
                    threshold=threshold.value,
                    actual_value=value,
                    details={
                        'operator': threshold.operator.value,
                        'condition_met': True,
                        'reason': 'Guard not found in response'
                    }
                )
            # Use ThresholdHelper for comparison
            comparison_result = self._threshold_helper.compare(threshold, value)

            return CheckResult(
                verdict=Verdict.FAIL if comparison_result else Verdict.PASS,
                guard_name=guard_name,
                threshold=threshold.value,
                actual_value=value,
                details={
                    'operator': threshold.operator.value,
                    'condition_met': comparison_result
                }
            )
        except Exception as e:
            logger.debug("Error in check evaluation: %s", str(e))
            raise

class GuardProcessor:
    """Handles processing of guard configurations."""

    DEFAULT_THRESHOLD = Threshold(value=0.0, operator=ComparisonOperator.GREATER_THAN)

    def __init__(self, guard_config: Union[str, Path, Dict]):
        self._evaluator = CheckEvaluator()

        self.guard_config_parser = GuardConfig(guard_config)

        self._response: Optional[Scanresponse] = None

    def process_guard_check(
        self,
        guard_name: str,
        threshold: Threshold,
        match_name: Optional[str] = None
    ) -> CheckResult:
        """Process a single guard check with action consideration."""
        try:
            if self._response is None:
                raise ValueError("Response cannot be nil to process the verdict")
            # Get raw evaluation
            check_result = self._evaluator.evaluate(self._response, guard_name, threshold, match_name)

            # SATYAMTODO: Why are we returning a new checkresult when thats what is coming here ?
            return CheckResult(
                verdict=check_result.verdict,
                guard_name=guard_name,
                threshold=check_result.threshold,
                actual_value=check_result.actual_value,
                details={
                    **check_result.details,
                }
            )
        except Exception as e:
            logger.debug("Error processing guard %s ", {guard_name})
            raise e

    def _process_simple_guard(self, guard: Guard) -> CheckResult:
        """Process a simple guard (no matches)."""
        thd = guard.threshold
        if thd is None:
            thd = self.DEFAULT_THRESHOLD

        return self.process_guard_check(
            guard.name,
            thd
        )

    def _process_match_guard(self, guard: Guard) -> List[CheckResult]:
        """Process a guard with matches."""
        results = []
        if not guard.matches:
            return results

        for match_name, _ in guard.matches.items():
            thd = guard.threshold
            if thd is None:
                thd = self.DEFAULT_THRESHOLD

            result = self.process_guard_check(
                guard.name,
                thd,
                match_name
            )
            results.append(result)

        return results

    def get_verdict(self, response: Scanresponse) -> ProcessorResult:
        self._response = response
        return self.process_config(self.guard_config_parser)

    def process_config(self, config_parser: GuardConfig) -> ProcessorResult:
        """Process the complete guard configuration."""
        try:
            failed_checks = []
            total_checks = 0

            for guard in config_parser.simple_guards:
                result = self._process_simple_guard(guard)
                total_checks += 1
                if result.verdict == Verdict.FAIL:
                    failed_checks.append(result)

            for guard in config_parser.match_guards:
                results = self._process_match_guard(guard)
                total_checks += len(results)
                failed_checks.extend([r for r in results if r.verdict == Verdict.FAIL])


            return ProcessorResult(
                verdict=Verdict.FAIL if failed_checks else Verdict.PASS,
                failed_checks=failed_checks,
                total_checks=total_checks,
                details={
                    'failed_checks_count': len(failed_checks),
                }
            )

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ConfigurationError(f"Failed to process guard configuration: {str(e)}") from e
