from typing import List, Optional

from acuvity.response.result import Verdict, GuardVerdict, OverallVerdicts
from acuvity.response.evaluator import ResponseEvaluator

from acuvity.models.scanresponse import Scanresponse
from acuvity.utils.logger import get_default_logger
from acuvity.guard.config import Guard, GuardConfig


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
    ) -> GuardVerdict:
        """Process a single guard check with action consideration."""
        try:
            if self._response is None:
                raise ValueError("Response cannot be nil to process the verdict")
            # Get raw evaluation
            return self._evaluator.evaluate(self._response, guard, match_name)
        except Exception as e:
            logger.debug("Error processing guard %s ", {guard.name})
            raise e

    def _process_simple_guard(self, guard: Guard) -> GuardVerdict:
        """Process a simple guard (no matches)."""
        return self.process_guard_check(guard)

    def _process_match_guard(self, guard: Guard) -> List[GuardVerdict]:
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

    def verdicts(self) -> OverallVerdicts:
        """Process the complete guard configuration."""
        try:
            failed_checks = []
            total_checks = 0

            for guard in self.guard_config.simple_guards:
                result = self._process_simple_guard(guard)
                total_checks += 1
                if result.verdict == Verdict.FAIL:
                    failed_checks.append(result)

            for guard in self.guard_config.match_guards:
                results = self._process_match_guard(guard)
                total_checks += len(results)
                failed_checks.extend([r for r in results if r.verdict == Verdict.FAIL])

            return OverallVerdicts(
                verdict=Verdict.FAIL if failed_checks else Verdict.PASS,
                failed_checks=failed_checks,
                total_checks=total_checks,
                details={
                    'failed_checks_count': len(failed_checks),
                }
            )

        except Exception as e:
            logger.debug("Error processing guard config: %s",{str(e)})
            raise ValueError(f"Failed to process guard configuration: {str(e)}") from e
