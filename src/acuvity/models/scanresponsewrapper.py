from acuvity.verdict_processing.core.guard_processor import CheckEvaluator
from acuvity.verdict_processing.core.response_processor import GuardCheck
from acuvity.verdict_processing.util.response_parser import ResponseParser
from acuvity.verdict_processing.util.threshold_helper import ThresholdHelper

from .scanresponse import Scanresponse


class ScanResponseWrapper:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """

    def __init__(self, scan_response: Scanresponse):
        if not isinstance(scan_response, Scanresponse):
            raise TypeError("Expected an instance of Scanresponse")
        self._scan_response = scan_response
        self._parser = ResponseParser()  # Use the existing ResponseParser
        self._threshold_helper = ThresholdHelper()
        self._evaluator = CheckEvaluator(self._parser, self._threshold_helper)

    def check(self, guard_name: str) -> GuardCheck:
        """
        Initiate a check for the specified guard.

        Args:
            guard_name: The name of the guard to check.

        Returns:
            GuardCheck: A chainable object for performing threshold checks.
        """
        return GuardCheck(self._evaluator, self._scan_response, guard_name)

    def __getattr__(self, name):
        """
        Delegate attribute access to the original Scanresponse object.
        """
        return getattr(self._scan_response, name)
