from pathlib import Path
from typing import Dict, Optional, Union

from acuvity.verdict_processing.constants import GuardName, Verdict
from acuvity.verdict_processing.core.guard_processor import (
    CheckEvaluator,
    GuardProcessor,
)
from acuvity.verdict_processing.models.result import CheckResult, ProcessorResult

from .scanresponse import Scanresponse


class ScanResponseWithVerdict:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """

    def __init__(self, scan_response: Scanresponse, guard_config: Optional[Union[str, Path, Dict]] = None):
        if not isinstance(scan_response, Scanresponse):
            raise TypeError("Expected an instance of Scanresponse")
        self._scan_response = scan_response
        self.verdict_details : Optional[ProcessorResult] = None
        self.guard_config = guard_config
        self._evaluator = CheckEvaluator()

    def verdict(self, guard_or_conf: Optional[Union[GuardName, str, Dict, Path]] = None) -> Union[ProcessorResult, CheckResult]:
        """
        Dynamically evaluates the scan response or retrieves a single guard's verdict.

        Args:
            input: Can be one of:
                - GuardName: Name of the guard for querying a specific guard's verdict.
                - str: Guard name or a path to a guard configuration file.
                - Dict or Path: Guard configuration to evaluate all guards.

        Returns:
            Union[ProcessorResult, CheckResult]:
                - ProcessorResult for overall evaluation.
                - CheckResult for a specific guard.
        """
        try:
            # Handle GuardName or guard name as string
            if guard_or_conf is None:
                # If no input, always return the overall verdict
                if self.verdict_details is None:
                    guard_config = self.guard_config
                    if guard_config is None:
                        raise ValueError("No guard configuration was passed or available in the instance.")
                    processor = GuardProcessor(guard_config)
                    self.verdict_details = processor.get_verdict(self._scan_response)
                return self.verdict_details

            if isinstance(guard_or_conf, GuardName) or (isinstance(guard_or_conf, str) and self._is_guard_name(guard_or_conf)):
                guard_name = guard_or_conf.value if isinstance(guard_or_conf, GuardName) else guard_or_conf
                if not self.verdict_details:
                    raise ValueError("Verdict details are not available. Call `verdict()` with a guard_config first.")

                for check in self.verdict_details.failed_checks:
                    if check.guard_name == guard_name:
                        return check

                # If not failed, return PASS
                return CheckResult(
                        verdict=Verdict.PASS,
                        guard_name=guard_name,
                        threshold=0.0,
                        actual_value=0.0,
                        details={"reason": "No voilations detected for the guard"}
                    )

            # Handle guard configuration evaluation

            guard_config = guard_or_conf or self.guard_config
            if not guard_config:
                raise ValueError("Guard config must be passed either to scan or verdict.")

            self.verdict_details = GuardProcessor(guard_config).get_verdict(self._scan_response)
            return self.verdict_details

        except Exception as e:
            raise ValueError(f"Failed to process verdict: {str(e)}") from e

    def _is_guard_name(self, guard: str) -> bool:
        """
        Check if the input string represents a valid guard name.

        Args:
            input: Input string to check.

        Returns:
            bool: True if the input matches a guard name, otherwise False.
        """
        # Check against GuardName enum values
        if guard in {guard.value for guard in GuardName}:
            return True
        return False

    def __getattr__(self, name):
        """
        Delegate attribute access to the original Scanresponse object.
        """
        return getattr(self._scan_response, name)
