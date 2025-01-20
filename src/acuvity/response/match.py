import os
from typing import List, Sequence, Union

from acuvity.guard.config import GuardConfig
from acuvity.guard.constants import GuardName
from acuvity.models.scanresponse import Scanresponse
from acuvity.response.processor import ResponseProcessor
from acuvity.response.result import GuardMatch, Matches, ResponseMatch


class ScanResponseMatch:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """
    def __init__(self, scan_response: Scanresponse, guard_config: GuardConfig,
                files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None):
        self._guard_config = guard_config
        self.scan_response = scan_response
        self._number_of_files = self._count_files(files)
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

        # compute the match
        try:
            self.match_details = ResponseProcessor(self.scan_response, self._guard_config).matches()
        except Exception as e:
            raise ValueError(f"Failed to process match: {str(e)}") from e

    def _count_files(self, files: Union[Sequence[Union[str, os.PathLike]], os.PathLike, str, None] = None) -> int:
        if files is None:
            return 0
        return len([files] if isinstance(files, (str, os.PathLike)) else files)

    def matches(self, file_index: int = -1, msg_index: int = -1) -> List[Matches]:
        """
        Returns the overall match of the scan response.
        """
        matches: List[Matches] = []
        # Helper to search one index
        def search_at_index(idx: int) -> Matches:
            if 0 <= idx < len(self.match_details):
                return self.match_details[idx]
            raise ValueError(f"Invalid index {idx}")

        # 1) If either index is given (not -1), search them
        if file_index != -1 or msg_index != -1:
            if file_index != -1:
                matches.append(search_at_index(file_index))
            if msg_index != -1:
                idx_msg = msg_index + self._number_of_files
                matches.append(search_at_index(idx_msg))
            return matches

        # 2) If both are -1, return all
        return self.match_details

    def guard_match(self, guard: GuardName, file_index: int = -1, msg_index: int = -1) -> List[GuardMatch]:
        """
        Retrieves a single guard's match.

        Args:
            guard: Name of the guard for querying a specific guard's match.
            file_index: guard check to run against which input file.
            msg_index: guard check to run aginst which input msg.

        Returns:
            The 1st found GuardMatch for a specific guard.
        """
        matches: List[GuardMatch] = []

        # Helper to search one index
        def search_at_index(idx: int):
            if 0 <= idx < len(self.match_details):
                for c in self.match_details[idx].matched_checks:
                    if c.guard_name == guard:
                        matches.append(c)
            else:
                raise ValueError(f"Index {idx} is out of range.")

        # 1) If either index is given (not -1), search them
        if file_index != -1 or msg_index != -1:
            if file_index != -1:
                search_at_index(file_index)
            if msg_index != -1:
                idx_msg = msg_index + self._number_of_files
                search_at_index(idx_msg)
        else:
            # 2) If both are -1, search all
            for check in self.match_details:
                for c in check.matched_checks:
                    if c.guard_name == guard:
                        matches.append(c)

        # 3) If no matches found, return a "default" match
        if not matches:
            matches.append(GuardMatch(
                response_match=ResponseMatch.NO,
                guard_name=guard,
                threshold="> 0.0",
                actual_value=0.0
            ))

        return matches

    def __getattr__(self, name):
        """
        Delegate attribute access to the original Scanresponse object.
        """
        return getattr(self.scan_response, name)
