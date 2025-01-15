from typing import List, Optional

from acuvity.guard.config import Guard, GuardConfig
from acuvity.models.scanresponse import Extraction, Scanresponse
from acuvity.response.evaluator import ResponseEvaluator
from acuvity.response.result import GuardMatch, Matches, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

class ResponseProcessor:
    """Handles processing of guard configurations."""

    def __init__(self, response: Scanresponse, guard_config: GuardConfig):
        self._evaluator = ResponseEvaluator()
        self.guard_config = guard_config
        self._response = response

    def process_guard_check(
        self,
        guard: Guard,
        extraction: Extraction,
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """Process a single guard check with action consideration."""
        try:
            # Get raw evaluation
            return self._evaluator.evaluate(extraction, guard, match_name)
        except Exception as e:
            logger.debug("Error processing guard %s ", {guard.name})
            raise e

    def _process_simple_guard(self, guard: Guard, extraction: Extraction) -> GuardMatch:
        """Process a simple guard (no matches)."""
        return self.process_guard_check(guard, extraction)

    def _process_match_guard(self, guard: Guard, extraction: Extraction) -> GuardMatch:
        """Process a guard with matches."""
        result_match = ResponseMatch.NO
        match_counter = 0
        for match_name, match_name_guard in guard.matches.items():
            result = self.process_guard_check(
                guard,
                extraction,
                match_name
            )
            # increment the match_counter only if eval is YES and it crosess the individual count_threshold .
            if result.response_match == ResponseMatch.YES and result.match_count >= match_name_guard.count_threshold:
                match_counter += result.match_count
            # if any one match, then flagged or if threshold given then check if greater.
            if match_counter >= guard.count_threshold:
                result_match = ResponseMatch.YES

        logger.debug(f"match guard {guard.name}, check {result_match}, total match {match_counter}, guard threshold {guard.count_threshold}")
        return GuardMatch(
                    response_match=result_match,
                    guard_name=guard.name,
                    threshold=str(guard.threshold),
                    actual_value=1.0,
                    match_count=match_counter
                )

    def matches(self) -> list[Matches]:
        """Process the complete guard configuration."""
        all_matches : list[Matches] = []
        try:
            if self._response.extractions is None:
                raise ValueError("response doesn't contain extractions")

            for ext in self._response.extractions:
                if ext.data is None:
                    continue
                matched_checks = []
                all_checks = []
                for guard in self.guard_config.simple_guards:
                    result = self._process_simple_guard(guard, ext)
                    if result.response_match == ResponseMatch.YES:
                        matched_checks.append(result)
                    all_checks.append(result)

                for guard in self.guard_config.match_guards:
                    results = self._process_match_guard(guard, ext)
                    if results.response_match == ResponseMatch.YES:
                        matched_checks.append(results)
                    all_checks.append(results)

                single_match =  Matches(
                    input_data=ext.data,
                    response_match=ResponseMatch.YES if matched_checks else ResponseMatch.NO,
                    matched_checks=matched_checks,
                    all_checks=all_checks
                )
                all_matches.append(single_match)
            return all_matches

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
