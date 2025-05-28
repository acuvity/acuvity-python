import os
from typing import List, Sequence, Union

from acuvity.guard.config import GuardConfig
from acuvity.guard.constants import GuardName
from acuvity.models.scanresponse import Scanresponse
from acuvity.response.processor import ResponseProcessor
from acuvity.response.result import GuardMatch, Matches, ResponseMatch


class ScanResponseMatch:
    """
    Wrapper for Scanresponse that adds functionality for checking guards against files or messages.

    This class processes a scan response against guard configurations to determine
    if any content violates the defined guard policies.
    """
    def __init__(self, scan_response: Scanresponse, guard_config: GuardConfig,
                files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None):
        """
        Initialize with scan results and guard configuration.

        Args:
            scan_response: The results from a content scan
            guard_config: Configuration defining which guards to check and their thresholds
            files: File(s) that were scanned (used to calculate correct indices)
        """
        self._guard_config = guard_config
        self.scan_response = scan_response
        self._number_of_files = self._count_files(files)
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

        # Process the scan response against the guard configuration
        try:
            self.match_details = ResponseProcessor(self.scan_response, self._guard_config).matches()
        except Exception as e:
            raise ValueError(f"Failed to process match: {str(e)}") from e

    def _count_files(self, files: Union[Sequence[Union[str, os.PathLike]], os.PathLike, str, None] = None) -> int:
        """Count the number of files to help calculate correct message indices."""
        if files is None:
            return 0
        return len([files] if isinstance(files, (str, os.PathLike)) else files)

    def matches(self, file_index: int = -1, msg_index: int = -1) -> List[Matches]:
        """
        Returns the match results for specified files or messages.

        Args:
            file_index: Specific file to check (-1 for all)
            msg_index: Specific message to check (-1 for all)

        Returns:
            List of Matches objects containing guard check results

        Notes:
            - Match results are ordered with files first, then messages
            - If both indices are -1, all results are returned
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
                # Message indices come after file indices
                idx_msg = msg_index + self._number_of_files
                matches.append(search_at_index(idx_msg))
            return matches

        # 2) If both are -1, return all matches
        return self.match_details

    def guard_match(self, guard: GuardName, file_index: int = -1, msg_index: int = -1) -> List[GuardMatch]:
        """
        Retrieves match results for a specific guard type.

        Args:
            guard: Name of the specific guard to check
            file_index: Specific file to check (-1 for all)
            msg_index: Specific message to check (-1 for all)

        Returns:
            List of GuardMatch objects for the specified guard

        Notes:
            - Returns a default "no match" result if no matches found
            - Can search in specific files/messages or across all content
        """
        matches: List[GuardMatch] = []
        if not GuardName.valid(str(guard)):
            raise ValueError(f"Invalid gaurd name, please provide one of the following {GuardName.values()}")

        # Helper to search for guard matches at a specific index
        def search_at_index(idx: int):
            if 0 <= idx < len(self.match_details):
                for c in self.match_details[idx].matched_checks:
                    if c.guard_name == guard:
                        matches.append(c)
            else:
                raise ValueError(f"Index {idx} is out of range.")

        # 1) If either index is given (not -1), search only those
        if file_index != -1 or msg_index != -1:
            if file_index != -1:
                search_at_index(file_index)
            if msg_index != -1:
                # Message indices come after file indices
                idx_msg = msg_index + self._number_of_files
                search_at_index(idx_msg)
        else:
            # 2) If both are -1, search across all matches
            for check in self.match_details:
                for c in check.matched_checks:
                    if c.guard_name == guard:
                        matches.append(c)

        # 3) If no matches found, return a "default" negative match
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
        Delegate attribute access to the wrapped Scanresponse object.
        This allows transparent access to all Scanresponse attributes.
        """
        return getattr(self.scan_response, name)
