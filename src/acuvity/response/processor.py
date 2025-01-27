from typing import List

from acuvity.guard.config import Guard, GuardConfig
from acuvity.models.scanresponse import Extraction, Scanresponse
from acuvity.response.helper import ResponseHelper
from acuvity.response.result import GuardMatch, Matches, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

class ResponseProcessor:
    """Handles processing of guard configurations."""

    def __init__(self, response: Scanresponse, guard_config: GuardConfig):
        self.guard_config = guard_config
        self._response = response

    def _process_guard(self, guard: Guard, extraction: Extraction) -> GuardMatch:
        """Process a guard with matches."""
        if guard.matches is None or len(guard.matches) == 0:
            return ResponseHelper.evaluate(extraction, guard)

        # Process guards with matchedqq
        result_match = ResponseMatch.NO
        match_counter = 0
        match_list : List[str] = []
        for match_name, match_name_guard in guard.matches.items():
            result = ResponseHelper.evaluate(extraction, guard, match_name)
            # increment the match_counter only if eval is YES and it crosess the individual count_threshold .
            if result.response_match == ResponseMatch.YES and result.match_count >= match_name_guard.count_threshold:
                match_counter += result.match_count
                match_list.append(match_name)
            # if any one match, then flagged or if threshold given then check if greater.
            if match_counter >= guard.count_threshold:
                result_match = ResponseMatch.YES

        logger.debug("match guard {%s} , check {%s}, total match {%s}, guard threshold {%s}, match_list {%s}",
                    guard.name, result_match, match_counter, guard.count_threshold, match_list)

        # reset the match_list
        if result_match == ResponseMatch.NO:
            match_list = []
        return GuardMatch(
                    response_match=result_match,
                    guard_name=guard.name,
                    threshold=str(guard.threshold),
                    actual_value=1.0,
                    match_count=match_counter,
                    match_values=match_list
                )

    def matches(self) -> List[Matches]:
        """Process the complete guard configuration."""
        all_matches : List[Matches] = []
        try:
            if self._response.extractions is None:
                raise ValueError("response doesn't contain extractions")

            for ext in self._response.extractions:
                if ext.data is None:
                    continue
                matched_checks = []
                all_checks = []
                for guard in self.guard_config.guards:
                    result = self._process_guard(guard, ext)
                    if result.response_match == ResponseMatch.YES:
                        matched_checks.append(result)
                    all_checks.append(result)

                single_match =  Matches(
                    input_data=ext.data,
                    response_match=ResponseMatch.YES if matched_checks else ResponseMatch.NO,
                    matched_checks=matched_checks,
                    all_checks=all_checks
                )
                all_matches.append(single_match)
            return all_matches

        except Exception as e:
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
