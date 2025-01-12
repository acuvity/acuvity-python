from pathlib import Path
from typing import Dict, List, Optional, Union

from ..models.scanresponse import Scanresponse
from ..utils.logger import get_default_logger

from .constants import (
    Verdict,
)
from ..guard.config import Guard, GuardConfig
from .result import CheckResult, ProcessorResult
from .parser import ResponseParser

logger = get_default_logger()

class CheckEvaluator:
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
                return CheckResult(
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

            return CheckResult(
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

class GuardProcessor:
    """Handles processing of guard configurations."""

    def __init__(self, guard_config: Union[str, Path, Dict]):
        self._evaluator = CheckEvaluator()

        self.guard_config_parser = GuardConfig(guard_config)

        self._response: Optional[Scanresponse] = None

    def process_guard_check(
        self,
        guard: Guard,
        match_name: Optional[str] = None
    ) -> CheckResult:
        """Process a single guard check with action consideration."""
        try:
            if self._response is None:
                raise ValueError("Response cannot be nil to process the verdict")
            # Get raw evaluation
            return self._evaluator.evaluate(self._response, guard, match_name)
        except Exception as e:
            logger.debug("Error processing guard %s ", {guard.name})
            raise e

    def _process_simple_guard(self, guard: Guard) -> CheckResult:
        """Process a simple guard (no matches)."""
        return self.process_guard_check(guard)

    def _process_match_guard(self, guard: Guard) -> List[CheckResult]:
        """Process a guard with matches."""
        results = []
        if not guard.matches:
            return results

        for match_name, _ in guard.matches.items():
            result = self.process_guard_check(
                guard,
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
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
