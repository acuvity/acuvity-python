from typing import Optional

from ..constants import GUARD_TO_SECTION, TOPIC_PREFIXES
from ..models.errors import ValidationError


class PathResolver:
    """Handles resolution of response paths for guards."""

    @staticmethod
    def get_path(guard_name: str, match_name: Optional[str] = None) -> str:
        """
        Get the check path based on guard type and optional match.

        Args:
            guard_name: Name of the guard
            match_name: Optional match name for match-based guards

        Returns:
            Resolved path in the response

        Raises:
            ValidationError: If guard type is unknown or path can't be resolved
        """
        section = GUARD_TO_SECTION.get(guard_name)
        if not section:
            raise ValidationError(f"Unknown guard type: {guard_name}")

        # Handle topics section with special prefixes
        if section == 'topics':
            prefix = TOPIC_PREFIXES.get(guard_name)
            if not prefix:
                raise ValidationError(f"Unknown topic prefix for guard: {guard_name}")

            if match_name:
                return f"{section}.{prefix}/{match_name}"
            return f"{section}.{prefix}"

        # Handle standard match paths
        if match_name:
            return f"{section}.{match_name}"

        # Handle direct paths
        return f"{section}.{guard_name}"
