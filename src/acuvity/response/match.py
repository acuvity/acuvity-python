import os
from typing import Iterable, Sequence, Union

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
                *messages: str,
                files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None):
        self._guard_config = guard_config
        self.scan_response = scan_response
        self._files = len(self.processed_files(files))
        self._msgs = messages
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

        # compute the match
        try:
            self.match_details = ResponseProcessor(self.scan_response, self._guard_config).matches()
        except Exception as e:
            raise ValueError(f"Failed to process match: {str(e)}") from e

    def processed_files(self, files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None)-> list[Union[str, os.PathLike]]:
        process_files: list[Union[str, os.PathLike]] = []

        if files is None:
            # No files to process; return an empty list
            pass
        elif isinstance(files, (str, os.PathLike)):
            # Single file (string or PathLike)
            process_files.append(files)
        elif isinstance(files, Iterable):
            # Multiple files
            for file in files:
                if not isinstance(file, (str, os.PathLike)):
                    raise ValueError("All items in 'files' must be str or os.PathLike")
                process_files.append(file)
        else:
            # If it's not None, not a single str/PathLike, and not Iterable, that's invalid
            raise ValueError(
                "Argument 'files' must be None, a str, a PathLike, or an Iterable of these."
            )
        return process_files

    def matches(self) -> list[Matches]:
        """
        Returns the overall match of the scan response.
        """
        return self.match_details

    def guard_match(self, guard: GuardName, file_index: int = -1, msg_index: int = -1) -> list[GuardMatch]:
        """
        Retrieves a single guard's match.

        Args:
            guard: Name of the guard for querying a specific guard's match.
            file_index: guard check to run against which input file.
            msg_index: guard check to run aginst which input msg.

        Returns:
            The 1st found GuardMatch for a specific guard.
        """
        matches: list[GuardMatch] = []

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
                idx_msg = msg_index + self._files
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
