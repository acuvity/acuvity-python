from typing import Any, Dict

from ..models import GuardResult, Verdict
from .base import GuardEvaluator


class SimpleThresholdGuard(GuardEvaluator):
    """Evaluator for simple threshold-based guards."""

    def evaluate(self, response_data: Dict[str, Any], guard_config: Dict[str, Any]) -> GuardResult:
        guard_name = guard_config.get('guard_name', guard_config.get('guard', ''))
        threshold_str = guard_config.get('threshold', '0')
        threshold = float(threshold_str.replace('>=', '').strip())

        # Get the value from response data
        response_value = response_data.get('exploits', {}).get(guard_name, 0)

        # Determine if threshold is exceeded
        is_exceeded = response_value >= threshold if '>=' in threshold_str else response_value > threshold

        verdict = Verdict.FAIL if is_exceeded else Verdict.PASS

        return GuardResult(
            verdict=verdict,
            guard_name=guard_name,
            details={'threshold_type': 'simple'},
            threshold=threshold,
            actual_value=response_value
        )
