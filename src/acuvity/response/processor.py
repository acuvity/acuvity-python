from typing import List

from acuvity.guard.config import Guard, GuardConfig
from acuvity.models.scanresponse import Extraction, Scanresponse
from acuvity.response.helper import ResponseHelper
from acuvity.response.result import GuardMatch, Matches, ResponseMatch
from acuvity.utils.logger import get_default_logger

logger = get_default_logger()

class ResponseProcessor:
    """
    Processes scan responses against guard configurations to identify policy violations.

    Evaluates content extractions against defined guards and aggregates the results.
    """

    def __init__(self, response: Scanresponse, guard_config: GuardConfig):
        """
        Initialize with scan response and guard configuration.

        Args:
            response: The scan response containing content extractions
            guard_config: Configuration defining guards and thresholds
        """
        self.guard_config = guard_config
        self._response = response

    def _process_guard(self, guard: Guard, extraction: Extraction) -> GuardMatch:
        """
        Process a single guard against an extraction.

        If guard has specific matches defined, each match is evaluated independently
        and results are aggregated based on count thresholds.

        Args:
            guard: The guard configuration to evaluate
            extraction: Content extraction to check against

        Returns:
            GuardMatch with results of the evaluation
        """
        # Simple case: guard with no specific matches to check
        if guard.matches is None or len(guard.matches) == 0:
            return ResponseHelper.evaluate(extraction, guard)

        # Complex case: guard with specific patterns/entities to match
        result_match = ResponseMatch.NO
        match_counter = 0
        match_list : List[str] = []

        # Check each specific match pattern defined in the guard
        for match_name, match_name_guard in guard.matches.items():
            result = ResponseHelper.evaluate(extraction, guard, match_name)

            # Track matches that exceed their individual thresholds
            if result.response_match == ResponseMatch.YES and result.match_count >= match_name_guard.count_threshold:
                match_counter += result.match_count
                match_list.append(match_name)

                # If total matches exceed the guard's overall threshold, flag as a match
                if match_counter >= guard.count_threshold:
                    result_match = ResponseMatch.YES

        logger.debug("match guard {%s} , check {%s}, total match {%s}, guard threshold {%s}, match_list {%s}",
                    guard.name, result_match, match_counter, guard.count_threshold, match_list)

        # Only keep match list if there was an overall match
        if result_match == ResponseMatch.NO:
            match_list = []

        return GuardMatch(
                    response_match=result_match,
                    guard_name=guard.name,
                    threshold=str(guard.threshold),
                    actual_value=1.0,  # Always 1.0 for aggregated matches
                    match_count=match_counter,
                    match_values=match_list
                )

    def matches(self) -> List[Matches]:
        """
        Process all guards against all extractions in the response.

        Evaluates each extraction against each guard in the config and
        aggregates results into a list of Matches objects.

        Returns:
            List of Matches objects, one per extraction

        Raises:
            ValueError: If response is missing extractions or processing fails
        """
        all_matches : List[Matches] = []
        try:
            if self._response.extractions is None:
                raise ValueError("response doesn't contain extractions")

            # Process each extraction separately
            for ext in self._response.extractions:
                if ext.data is None:
                    continue

                matched_checks = []  # Guards that matched (violations)
                all_checks = []      # All guard checks performed

                # Check each guard against this extraction
                for guard in self.guard_config.guards:
                    result = self._process_guard(guard, ext)

                    # Track violations and all checks separately
                    if result.response_match == ResponseMatch.YES:
                        matched_checks.append(result)
                    all_checks.append(result)

                # Create Matches object for this extraction's results
                single_match = Matches(
                    input_data=ext.data,
                    response_match=ResponseMatch.YES if matched_checks else ResponseMatch.NO,
                    matched_checks=matched_checks,
                    all_checks=all_checks
                )
                all_matches.append(single_match)

            return all_matches

        except Exception as e:
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
