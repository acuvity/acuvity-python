from acuvity.guard.constants import GuardName
from acuvity.guard.config import GuardConfig
from acuvity.responseprocessor.constants import Verdict
from acuvity.responseprocessor.processor import (
    GuardProcessor,
)
from acuvity.responseprocessor.result import GuardVerdict, OverallVerdicts

from ..models.scanresponse import Scanresponse

class ScanResponseWithVerdict:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """
    def __init__(self, scan_response: Scanresponse, guard_config: GuardConfig):
        self._scan_response = scan_response
        self._guard_config = guard_config
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

        # compute the verdict
        try:
            self.verdict_details = GuardProcessor(self._scan_response, self._guard_config).verdicts()
        except Exception as e:
            raise ValueError(f"Failed to process verdict: {str(e)}") from e

    def verdicts(self) -> OverallVerdicts:
        """
        Returns the overall verdict of the scan response.
        """
        return self.verdict_details

    def guard_verdict(self, guard: GuardName) -> GuardVerdict:
        """
        Retrieves a single guard's verdict.

        Args:
            guard: Name of the guard for querying a specific guard's verdict.

        Returns:
            GuardVerdict for a specific guard.
        """
        for check in self.verdict_details.failed_checks:
            if check.guard_name == guard:
                return check

        # If not failed, return PASS
        return GuardVerdict(
                verdict=Verdict.PASS,
                guard_name=guard,
                threshold=0.0,
                actual_value=0.0,
                details={"reason": "No voilations detected for the guard"}
        )

    def __getattr__(self, name):
        """
        Delegate attribute access to the original Scanresponse object.
        """
        return getattr(self._scan_response, name)
