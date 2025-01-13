from typing import List, Optional

from acuvity.guard.config import Guard, GuardConfig
from acuvity.models.scanresponse import Scanresponse
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
        match_name: Optional[str] = None
    ) -> GuardMatch:
        """Process a single guard check with action consideration."""
        try:
            if self._response is None:
                raise ValueError("Response cannot be nil to process the verdict")
            # Get raw evaluation
            return self._evaluator.evaluate(self._response, guard, match_name)
        except Exception as e:
            logger.debug("Error processing guard %s ", {guard.name})
            raise e

    def _process_simple_guard(self, guard: Guard) -> GuardMatch:
        """Process a simple guard (no matches)."""
        return self.process_guard_check(guard)

    def _process_match_guard(self, guard: Guard) -> List[GuardMatch]:
        """Process a guard with matches."""
        results = []
        if not guard.matches:
            return results

        for match_name, _ in guard.matches.items():
            result = self.process_guard_check(
                guard,
                match_name
            )
            results.append(result)

        return results

    def verdicts(self) -> Matches:
        """Process the complete guard configuration."""
        try:
            matched_checks = []
            all_checks = []

            for guard in self.guard_config.simple_guards:
                result = self._process_simple_guard(guard)
                if result.response_match == ResponseMatch.YES:
                    matched_checks.append(result)
                all_checks.append(result)

            for guard in self.guard_config.match_guards:
                results = self._process_match_guard(guard)
                matched_checks.extend([r for r in results if r.response_match == ResponseMatch.YES])
                all_checks.append(results)

            return Matches(
                response_match=ResponseMatch.YES if matched_checks else ResponseMatch.NO,
                matched_checks=matched_checks,
                all_checks=all_checks
            )

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
