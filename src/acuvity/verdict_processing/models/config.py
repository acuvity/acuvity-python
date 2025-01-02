from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MatchThresholdConfig:
    """Configuration for a match threshold."""
    threshold: str

@dataclass
class GuardConfig:
    """Configuration for a single guard.

    Examples:
        Simple guard:
        {
            "guard_name": "prompt_injection",
            "threshold": ">= 0.7",
            "action": "deny"
        }

        Guard with matches:
        {
            "guard_name": "modality",
            "matches": {
                "unknown": {"threshold": "0.7"},
                "document": {"threshold": "0.7"}
            },
            "action": "allow"
        }
    """
    # Fields can be either guard_name or guard
    guard_name: Optional[str] = None
    guard: Optional[str] = None

    # Threshold is required for simple guards, optional for guards with matches
    threshold: Optional[str] = None

    # Action defaults to deny if not specified
    action: str = "deny"

    # Matches for complex guards
    matches: Optional[Dict[str, Dict[str, str]]] = None

    def __post_init__(self):
        """Validate and normalize the guard configuration."""
        # Ensure either guard_name or guard is present
        if not self.guard_name and not self.guard:
            raise ValueError("Either guard_name or guard must be specified")

        # If guard is specified but guard_name isn't, use guard as guard_name
        if not self.guard_name:
            self.guard_name = self.guard

        # For simple guards, threshold is required
        if not self.matches and not self.threshold:
            raise ValueError("Threshold is required for simple guards")

        # For guards with matches, validate match structure
        if self.matches:
            for key, value in self.matches.items():
                if not isinstance(value, dict) or 'threshold' not in value:
                    raise ValueError(f"Invalid match configuration for {key}")

        # Normalize action to lowercase
        self.action = self.action.lower()
        if self.action not in ['allow', 'deny']:
            raise ValueError(f"Invalid action: {self.action}")

@dataclass
class ProcessorConfig:
    """Overall configuration for guard processing.

    The config should have a 'guardrails' list containing guard configurations.
    Each guard configuration can be either a simple threshold guard or a
    guard with matches.
    """
    guardrails: List[Dict[str, Any]]
    guards: List[GuardConfig] = field(init=False)

    def __post_init__(self):
        """Convert guard dictionaries to GuardConfig objects."""
        try:
            self.guards = []
            for guard in self.guardrails:
                # Convert each guard dict to GuardConfig
                guard_config = (
                    guard if isinstance(guard, GuardConfig)
                    else GuardConfig(**guard)
                )
                self.guards.append(guard_config)
        except Exception as e:
            raise ValueError(f"Invalid guard configuration: {str(e)}") from e

    @property
    def simple_guards(self) -> List[GuardConfig]:
        """Get all simple guards (without matches)."""
        return [g for g in self.guards if not g.matches]

    @property
    def match_guards(self) -> List[GuardConfig]:
        """Get all guards with matches."""
        return [g for g in self.guards if g.matches]
