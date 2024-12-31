from typing import Any, Dict, Union

from ...utils.logger import get_default_logger
from ..constants import ThresholdOperator, Verdict
from ..models.config import GuardConfig, ProcessorConfig
from ..models.errors import ConfigurationError
from ..models.result import CheckResult, ProcessorResult
from ..util.response_parser import ResponseParser
from ..util.threshold_helper import ThresholdHelper

#from ..utils.response_parser import Th

logger = get_default_logger()

class VerdictProcessor:
    """
    Main processor for response checking and guard configuration processing.

    This class provides a unified interface for:
    1. Direct response checks using a fluent interface
    2. Processing complete guard configurations

    Example usage:
        processor = VerdictProcessor(response_data)

        # Direct check
        result = processor.check("prompt_injection").threshold_greater_than(0.6)

        # Config-based check
        verdict = processor.get_verdict_from_guardconfig(guard_config)
    """

    def __init__(self, response: Dict[str, Any]):
        """
        Initialize the processor with response data.

        Args:
            response: The response dictionary to process
        """
        self._response = response
        self._parser = ResponseParser()
        self._threshold_helper = ThresholdHelper()

        # Validate response structure
        self._parser.validate_response(response)

    class CheckBuilder:
        """Builder for fluent check interface. Inner class to maintain encapsulation."""

        def __init__(self, processor: 'VerdictProcessor', check_path: str):
            self.processor = processor
            self.check_path = check_path

        def threshold_greater_than(self, threshold: float) -> CheckResult:
            """Check if value is greater than threshold."""
            return self.processor.perform_check(
                self.check_path,
                threshold,
                ThresholdOperator.GREATER_THAN
            )

        def threshold_less_than(self, threshold: float) -> CheckResult:
            """Check if value is less than threshold."""
            return self.processor.perform_check(
                self.check_path,
                threshold,
                ThresholdOperator.LESS_THAN
            )

        def equals(self, value: float) -> CheckResult:
            """Check if value equals the specified value."""
            return self.processor.perform_check(
                self.check_path,
                value,
                ThresholdOperator.EQUAL
            )

    def check(self, path: str) -> CheckBuilder:
        """
        Start a fluent check interface for the specified path.

        Args:
            path: The path to check in dot notation (e.g., "exploits.prompt_injection")

        Returns:
            CheckBuilder: A builder for the check
        """
        return self.CheckBuilder(self, path)

    def perform_check(
        self,
        path: str,
        threshold: float,
        operator: ThresholdOperator
    ) -> CheckResult:
        """
        Perform a single check operation.

        Args:
            path: Path to the value to check
            threshold: Threshold value
            operator: Comparison operator

        Returns:
            CheckResult: The result of the check
        """
        try:
            value = self._parser.get_value(self._response, path)
            # Convert threshold to float if it's a simple numeric threshold
            if isinstance(threshold, (int, float)):
                threshold_value = float(threshold)
            else:
                # Parse threshold string if it includes operator
                threshold_value, parsed_operator = self._threshold_helper.parse_threshold(threshold)
                operator = parsed_operator

            exceeds = self._threshold_helper.compare(value, threshold_value, operator)

            return CheckResult(
                verdict=Verdict.FAIL if exceeds else Verdict.PASS,
                check_name=path,
                threshold=threshold,
                actual_value=float(value),
                details={
                    'operator': operator,
                    'comparison_result': exceeds
                }
            )
        except Exception as e:
            logger.debug("Error performing check: %s", {str(e)})
            raise

    def get_verdict_from_guardconfig(
        self,
        config: Union[Dict[str, Any], ProcessorConfig]
    ) -> ProcessorResult:
        """
        Process a complete guard configuration.

        Args:
            config: Guard configuration dictionary or ProcessorConfig object

        Returns:
            ProcessorResult: The result of processing all guards
        """
        try:
            # Convert dict config to ProcessorConfig if needed
            if isinstance(config, dict):
                config = ProcessorConfig(**config)

            failed_checks = []
            total_checks = 0

            for guard in config.guards:
                # Convert dict to GuardConfig if needed
                if isinstance(guard, dict):
                    guard = GuardConfig(**guard)

                # Parse threshold and operator from config
                threshold_value, operator = self._threshold_helper.parse_threshold(guard.threshold)

                # Handle simple threshold guards
                if not guard.matches:
                    check_result = self.perform_check(
                        guard.guard_name,
                        threshold_value,
                        operator
                    )
                    total_checks += 1

                    if check_result.verdict == Verdict.FAIL:
                        failed_checks.append(check_result)

                # Handle complex match guards
                else:
                    for match_name, _ in guard.matches.items():
                        check_path = f"{guard.guard_name}.{match_name}"
                        check_result = self.perform_check(
                            check_path,
                            threshold_value,
                            operator
                        )
                        total_checks += 1

                        if check_result.verdict == Verdict.FAIL:
                            failed_checks.append(check_result)

            return ProcessorResult(
                verdict=Verdict.FAIL if failed_checks else Verdict.PASS,
                failed_checks=failed_checks,
                total_checks=total_checks,
                details={
                    'config_type': 'guard_config',
                    'failed_checks_count': len(failed_checks)
                }
            )

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ConfigurationError(f"Failed to process guard configuration: {str(e)}") from e
