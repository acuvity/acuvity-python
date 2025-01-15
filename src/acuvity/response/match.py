from acuvity.guard.config import GuardConfig
from acuvity.guard.constants import GuardName
from acuvity.models.scanresponse import Scanresponse
from acuvity.response.processor import ResponseProcessor
from acuvity.response.result import GuardMatch, Matches, ResponseMatch


class ScanResponseMatch:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """
    def __init__(self, scan_response: Scanresponse, guard_config: GuardConfig):
        self._guard_config = guard_config
        self.scan_response = scan_response
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

        # compute the match
        try:
            self.match_details = ResponseProcessor(self.scan_response, self._guard_config).matches()
        except Exception as e:
            raise ValueError(f"Failed to process match: {str(e)}") from e

    def matches(self) -> list[Matches]:
        """
        Returns the overall match of the scan response.
        """
        return self.match_details

    def guard_match(self, guard: GuardName) -> GuardMatch:
        """
        Retrieves a single guard's match.

        Args:
            guard: Name of the guard for querying a specific guard's match.

        Returns:
            The 1st found GuardMatch for a specific guard.
        """
        for match in (
                c
                for check in self.match_details
                for c in check.matched_checks
                if c.guard_name == guard
            ):
            return match

        # If not failed, return PASS
        return GuardMatch(
                response_match=ResponseMatch.NO,
                guard_name=guard,
                threshold=str("> 0.0"),
                actual_value=0.0
        )

    def __getattr__(self, name):
        """
        Delegate attribute access to the original Scanresponse object.
        """
        return getattr(self.scan_response, name)
