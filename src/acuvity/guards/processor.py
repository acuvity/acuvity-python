import logging
from typing import Any, Dict, List

from .evals.base import GuardEvaluator
from .evals.matcheseval import MatchesGuard
from .evals.simpleeval import SimpleThresholdGuard
from .exceptions import GuardProcessingError
from .models import GuardResult, Verdict

logger = logging.getLogger(__name__)

class GuardProcessor:
    """Main class for processing guards and determining verdicts."""

    def __init__(self):
        self._evaluators = {
            'simple': SimpleThresholdGuard(),
            'matches': MatchesGuard()
        }

    def get_verdict_from_guardconfig(
        self,
        guard_config: List[Dict[str, Any]],
        response: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process guard configuration and response to determine overall verdict.

        Args:
            guard_config: List of guard configurations
            response: Response data to evaluate

        Returns:
            Dict containing overall verdict and detailed results
        """
        try:
            results = []
            for guard in guard_config:
                evaluator = self._get_evaluator(guard)
                result = evaluator.evaluate(response, guard)
                results.append(result)

            # Determine overall verdict
            failing_results = [r for r in results if r.verdict == Verdict.FAIL]
            overall_verdict = Verdict.FAIL if failing_results else Verdict.PASS

            return {
                'verdict': overall_verdict,
                'details': {
                    'failing_guards': [
                        {
                            'guard_name': r.guard_name,
                            'threshold': r.threshold,
                            'actual_value': r.actual_value,
                            **r.details
                        }
                        for r in failing_results
                    ],
                    'total_guards_evaluated': len(results),
                    'total_failing_guards': len(failing_results)
                }
            }

        except Exception as e:
            logger.error(f"Error processing guard config: {str(e)}")
            raise GuardProcessingError(f"Failed to process guard configuration: {str(e)}")

    def _get_evaluator(self, guard_config: Dict[str, Any]) -> GuardEvaluator:
        """Get the appropriate evaluator for the guard configuration."""
        if 'matches' in guard_config:
            return self._evaluators['matches']
        return self._evaluators['simple']
