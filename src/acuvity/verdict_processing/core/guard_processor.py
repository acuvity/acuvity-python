from typing import Any, Dict, List, Union

from ...utils.logger import get_default_logger
from ..constants import GUARD_TO_SECTION, TOPIC_PREFIXES, ThresholdOperator, Verdict
from ..models.config import GuardConfig, ProcessorConfig
from ..models.errors import ConfigurationError, ValidationError
from ..models.result import CheckResult, ProcessorResult
from ..util.threshold_helper import ThresholdHelper
from .evaluator import CheckEvaluator

logger = get_default_logger()

class GuardProcessor:
    """Handles processing of guard configurations."""

    def __init__(self, response: Dict[str, Any], evaluator: CheckEvaluator, threshold_helper: ThresholdHelper):
        self._validate_response_sections(response)
        self._response = response
        self._evaluator = evaluator
        self._threshold_helper = threshold_helper

    def _validate_response_sections(self, response: Dict[str, Any]) -> None:
        """Validate that all required sections exist in response."""
        required_sections = set(GUARD_TO_SECTION.values())
        missing_sections = required_sections - set(response.keys())
        if missing_sections:
            raise ValidationError(f"Response missing required sections: {missing_sections}")

    def _get_check_path(self, guard_name: str, match_name: str = None) -> str:
        """
        Get the check path based on guard type and optional match.
        Handles special cases for different sections.
        """
        section = GUARD_TO_SECTION.get(guard_name)
        if not section:
            raise ValidationError(f"Unknown guard type: {guard_name}")

        # Handle topics section with special prefixes
        if section == 'topics':
            prefix = TOPIC_PREFIXES.get(guard_name)
            if not prefix:
                raise ValidationError(f"Unknown topic prefix for guard: {guard_name}")

            if match_name:
                return f"{section}.{prefix}/{match_name}"
            return f"{section}.{prefix}"

        # Handle standard match paths
        if match_name:
            return f"{section}.{match_name}"

        # Handle direct paths
        return f"{section}.{guard_name}"

    def process_guard_check(
        self,
        path: str,
        threshold: Union[float, str],
        operator: ThresholdOperator,
        action: str
    ) -> CheckResult:
        """Process a single guard check with action consideration."""
        try:
            # Get raw evaluation
            check_result = self._evaluator.evaluate(self._response, path, threshold, operator)

            # Determine final verdict based on action
            if action.lower() == "deny":
                final_verdict = Verdict.FAIL if check_result.verdict == Verdict.PASS else Verdict.PASS
            else:  # "allow"
                final_verdict = check_result.verdict

            return CheckResult(
                verdict=final_verdict,
                check_name=path,
                threshold=check_result.threshold,
                actual_value=check_result.actual_value,
                details={
                    **check_result.details,
                    'action': action,
                    'section': path.split('.')[0]
                }
            )
        except Exception as e:
            logger.debug("Error processing guard check for path %s ", {path})
            raise e

    def _process_simple_guard(self, guard: GuardConfig) -> CheckResult:
        """Process a simple guard (no matches)."""
        check_path = self._get_check_path(guard.guard_name)
        threshold_value, operator = self._threshold_helper.parse_threshold(guard.threshold)

        return self.process_guard_check(
            check_path,
            threshold_value,
            operator,
            guard.action
        )

    def _process_match_guard(self, guard: GuardConfig) -> List[CheckResult]:
        """Process a guard with matches."""
        results = []
        if not guard.matches:
            return results

        for match_name, match_config in guard.matches.items():
            check_path = self._get_check_path(guard.guard_name, match_name)
            threshold_value, operator = self._threshold_helper.parse_threshold(match_config['threshold'])

            result = self.process_guard_check(
                check_path,
                threshold_value,
                operator,
                guard.action
            )
            results.append(result)

        return results

    def process_config(self, config: ProcessorConfig) -> ProcessorResult:
        """Process the complete guard configuration."""
        try:
            # Convert to ProcessorConfig if needed
            if isinstance(config, dict):
                config = ProcessorConfig(**config)

            failed_checks = []
            total_checks = 0

            for guard in config.simple_guards:
                result = self._process_simple_guard(guard)
                total_checks += 1
                if result.verdict == Verdict.FAIL:
                    failed_checks.append(result)

            for guard in config.match_guards:
                results = self._process_match_guard(guard)
                total_checks += len(results)
                failed_checks.extend([r for r in results if r.verdict == Verdict.FAIL])


            return ProcessorResult(
                verdict=Verdict.FAIL if failed_checks else Verdict.PASS,
                failed_checks=failed_checks,
                total_checks=total_checks,
                details={
                    'failed_checks_count': len(failed_checks),
                    'sections_checked': sorted(set(r.details['section'] for r in failed_checks))
                }
            )

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ConfigurationError(f"Failed to process guard configuration: {str(e)}") from e
