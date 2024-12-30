from typing import Any, Dict

from ..models import GuardResult, Verdict
from .base import GuardEvaluator


class MatchesGuard(GuardEvaluator):
    """Evaluator for guards with multiple match conditions."""

    def evaluate(self, response_data: Dict[str, Any], guard_config: Dict[str, Any]) -> GuardResult:
        guard_name = guard_config.get('guard_name', guard_config.get('guard', ''))
        matches = guard_config.get('matches', {})

        # Get the appropriate section from response data based on guard name
        response_section = self._get_response_section(guard_name, response_data)

        failed_matches = []
        max_threshold_exceeded = 0.0
        threshold_exceeded = 0.0

        for match_key, match_config in matches.items():
            threshold = float(match_config.get('threshold', 0))
            actual_value = response_section.get(match_key, 0)

            if actual_value >= threshold:
                failed_matches.append({
                    'key': match_key,
                    'threshold': threshold,
                    'actual_value': actual_value
                })
                max_threshold_exceeded = max(max_threshold_exceeded, actual_value)
                threshold_exceeded = threshold

        verdict = Verdict.FAIL if failed_matches and guard_config.get('action') == 'deny' else Verdict.PASS

        return GuardResult(
            verdict=verdict,
            guard_name=guard_name,
            details={
                'threshold_type': 'matches',
                'failed_matches': failed_matches
            },
            threshold=threshold_exceeded,
            actual_value=max_threshold_exceeded
        )

    def _get_response_section(self, guard_name: str, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get the appropriate section from response data based on guard name."""
        guard_to_section = {
            'modality': 'modalities',
            'language': 'languages',
            'image_classifier': 'topics',
            'corporate_classifier': 'topics',
            'content_classifier': 'topics',
            'generic_classifier': 'intent',
            'pattern_detector': 'detections'
        }

        section_name = guard_to_section.get(guard_name, guard_name)
        return response_data.get(section_name, {})
