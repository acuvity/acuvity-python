from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from .constants import GuardName
from .errors import (
    GuardConfigError,
    GuardConfigValidationError,
    GuardThresholdParsingError,
)
from .threshold import DEFAULT_THRESHOLD, Threshold


@dataclass(frozen=True)
class Match:
    """Immutable match configuration"""
    threshold: Threshold
    redact: bool = False
    count_threshold: int = 0

    @classmethod
    def create(
        cls,
        threshold: str | Threshold = DEFAULT_THRESHOLD,
        redact: bool = False,
        count_threshold: int = 0
    ) -> "Match":
        """
        Create a Match with type hints for better IDE support.

        Args:
            threshold: Threshold as string (e.g. '>= 0.8') or Threshold object
            redact: Whether to redact matches
            count_threshold: Minimum count threshold
        """
        if isinstance(threshold, str):
            threshold = Threshold(threshold)

        return cls(
            threshold=threshold,
            redact=redact,
            count_threshold=count_threshold
        )

@dataclass(frozen=True)
class Guard:
    """Immutable guard configuration"""
    name: GuardName
    matches: Dict[str, Match]
    threshold: Threshold
    count_threshold: int = 0

    @classmethod
    def create(
        cls,
        name: str | GuardName,
        matches: Dict[str, Match] | None = None,
        threshold: str | Threshold = DEFAULT_THRESHOLD,
        count_threshold: int = 0
    ) -> "Guard":
        """
        Create a Guard with type hints for better IDE support.

        Args:
            name: Guard name (string or GuardName enum)
            matches: Dictionary of match configurations
            threshold: Threshold as string (e.g. '>= 0.8') or Threshold object
            count_threshold: Minimum count threshold

        Raises:
            GuardConfigValidationError: If guard name is invalid
        """
        # Convert string to GuardName if needed
        if isinstance(name, str):
            guard_name = GuardName.get(name)
            if guard_name is None:
                valid_names = ", ".join(GuardName.values())
                raise GuardConfigValidationError(
                    f"Invalid guard name: {name}. Must be one of: {valid_names}"
                )
        else:
            guard_name = name

        if isinstance(threshold, str):
            threshold = Threshold(threshold)

        return cls(
            name=guard_name,
            matches=matches or {},
            threshold=threshold,
            count_threshold=count_threshold
        )

class GuardConfig:
    """
    Parser for guard configuration files.

    This class handles parsing of guard configuration files in YAML format,
    validating their contents, and converting between analyzer names and IDs.

    The parser handles two types of guards:
    1. Match Guards: Guards with a 'matches' section (e.g., pii_detector)
    2. Simple Guards: Guards without matches (e.g., prompt_injection, toxicity)
    """

    def __init__(self, config: Optional[Union[str, Path, Dict, List[Guard]]] = None):
        """
        Initialize parser with analyzer mapping.

        Args:
            config: Configuration as a string, filepath or dictionary
        """
        self._parsed_guards: List[Guard] = []

        # Handle default configuration
        if config is None:
            for guard in GuardName:
                # skip keyword detector in default
                if guard != GuardName.KEYWORD_DETECTOR:
                    self._parsed_guards.append(Guard(
                        name=guard,
                        matches={},
                        threshold=DEFAULT_THRESHOLD,
                        count_threshold=0,
                    ))
            return

        # Use the config provided
        self._parse_config(config)

    @staticmethod
    def load_yaml(path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load and parse YAML file.

        Args:
            path: Path to YAML file

        Returns:
            Parsed YAML content as dictionary

        Raises:
            GuardConfigError: If file cannot be read or parsed
        """
        try:
            with open(path, encoding='utf-8') as f:
                return yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            raise GuardConfigError(f"Failed to load config file: {e}") from e

    def _parse_config(self, config: Union[str, Path, Dict, List[Guard]]) -> List[Guard]:
        """
        Parse guard configuration from file or dictionary.

        Args:
            config: Path to YAML file or dictionary containing configuration

        Returns:
            List of parsed Guard objects

        Raises:
            GuardConfigError: If configuration is invalid
        """
        # Handle list of guard dictionaries
        if isinstance(config, list) and all(isinstance(guard, Guard) for guard in config):
            self._parsed_guards = [self._parse_guard_obj(guard) for guard in config
                              if self._validate_guard(guard)]
            return self._parsed_guards

        if isinstance(config, (str, Path)):
            config_data = self.load_yaml(config)
        else:
            config_data = config


        try:
            # Handle both single guard and multiple guardrails format
            guards = config_data.get('guardrails', [config_data])
            if not isinstance(guards, list):
                guards = [guards]

            self._parsed_guards = [self._parse_guard(guard) for guard in guards
                              if self._validate_guard(guard)]
            return self._parsed_guards

        except Exception as e:
            raise GuardConfigError(f"Failed to parse config: {e}") from e

    def _validate_guard(self, guard: Union[Dict, Guard]) -> bool:
        """
        Validate individual guard configuration.

        Args:
            guard: Guard configuration dictionary

        Returns:
            True if guard is valid

        Raises:
            GuardConfigValidationError: If guard configuration is invalid
        """
        if isinstance(guard, Guard) and not GuardName.valid(str(guard.name)):
                raise GuardConfigValidationError("Guard must have a valid name")
        elif isinstance(guard, Dict):
            if 'name' not in guard:
                raise GuardConfigValidationError(f"Guard must have a name, but give guard is:", guard)

            if not GuardName.valid(guard['name']):
                raise GuardConfigValidationError(f"Guard name not present {guard['name']}")

        return True

    def parse_match_obj(self, match_key: str, match_obj: Match | None) -> Match:
        """
        Parse an existing Match object, applying validation and defaults if needed.

        Args:
            match_key: Key identifying the match
            match_obj: Match object to parse, or None to use defaults

        Returns:
            Match: Validated Match object with defaults applied if needed

        Raises:
            GuardConfigValidationError: If threshold validation fails
        """
        # Handle None case
        if match_obj is None:
            return Match.create()

        try:
            # Use existing values or defaults
            threshold = match_obj.threshold or DEFAULT_THRESHOLD

            return Match.create(
                threshold=threshold,
                redact=match_obj.redact,
                count_threshold=match_obj.count_threshold
            )

        except ValueError as e:
            raise GuardConfigValidationError(
                f"Invalid match configuration for '{match_key}': {str(e)}"
            ) from e

    def _parse_match(self, match_key: str, match_data: Dict) -> Match:
        """
        Parse match configuration.

        Args:
            match_key: Key identifying the match
            match_data: Match configuration dictionary

        Returns:
            Match object
        """
        threshold = DEFAULT_THRESHOLD
        if match_data and 'threshold' in match_data:
            try:
                threshold = Threshold(match_data['threshold'])
            except GuardConfigValidationError as e:
                raise GuardConfigValidationError(f"Invalid threshold for match {match_key}") from e

            return Match(
                threshold=threshold,
                redact=match_data.get('redact', False),
                count_threshold=match_data.get('count_threshold', 0)
            )
        return Match(
            threshold=threshold,
            redact= False,
            count_threshold=0
        )

    @property
    def match_guards(self) -> List[Guard]:
        """
        Returns list of guard configurations that have match patterns.

        Returns:
            List of Guard objects that have 'matches' section
        """
        return [guard for guard in self._parsed_guards
                if guard.matches]

    @property
    def parsed_guards(self) -> List[Guard]:
        """
        Returns list of guard configurations that have match patterns.

        Returns:
            List of Guard objects that have 'matches' section
        """
        return self._parsed_guards

    @property
    def simple_guards(self) -> List[Guard]:
        """
        Returns list of guard configurations without match patterns.

        Returns:
            List of Guard objects that don't have 'matches' section
        """
        return [guard for guard in self._parsed_guards
                if not guard.matches]

    @property
    def guard_names(self) -> List[GuardName]:
        """
        Returns the list of all guards configured
        """
        names = []
        for g in self._parsed_guards:
            names.append(g.name)
        return names

    @property
    def redaction_keys(self) -> List[str]:
        """
        Returns the list of the keys that have redaction set.
        """
        redact_keys = []
        for g in self.match_guards:
            for key, matches in g.matches.items():
                if matches.redact:
                    redact_keys.append(key)
        return redact_keys

    @property
    def keywords(self) -> List[str]:
        """
        Returns the list of the keys that have redaction set.
        """
        keywords = []
        for g in self.match_guards:
            if g.name == 'keyword_detector':
                for key, matches in g.matches.items():
                    if matches.redact:
                        keywords.append(key)
        return keywords

    def _parse_guard(self, guard: Dict) -> Guard:
        """
        Parse individual guard configuration.

        Args:
            guard: Guard configuration dictionary

        Returns:
            Guard object

        Raises:
            GuardConfigValidationError: If guard configuration is invalid
        """
        name = guard['name']


        # Parse top-level threshold
        threshold = DEFAULT_THRESHOLD
        if 'threshold' in guard:
            try:
                threshold = Threshold(guard.get('threshold', '>= 0.0'))
            except GuardConfigValidationError as e:
                raise e

        # Parse matches
        matches = {}
        for match_key, match_data in guard.get('matches', {}).items():
            matches[match_key] = self._parse_match(match_key, match_data)

        guard_name = GuardName.get(name)
        if guard_name:
            return Guard(
                name=guard_name,
                matches=matches,
                threshold=threshold,
                count_threshold=guard.get('count_threshold', 0)
            )

    def _parse_guard_obj(self, guard: Guard) -> Guard:
        """
        Parse (or re-validate) an existing Guard object.

        Args:
            guard: An already-instantiated Guard object.

        Returns:
            A Guard object (either the same or a new one) that has been
            re-validated, re-initialized, or finalized.

        Raises:
            ConfigValidationError: If guard configuration is invalid.
        """
        try:
            # Convert guard.name to GuardName if it's not already
            guard_name = guard.name
            if not isinstance(guard_name, GuardName):
                # If .get() can raise an error, it'll be caught by this try block
                guard_name = GuardName.get(guard_name)

            # Parse or confirm the threshold
            threshold = guard.threshold if guard.threshold is not None else DEFAULT_THRESHOLD
            # If threshold parsing can fail, wrap it similarly:
            # threshold = Threshold(guard.threshold)

            # Re-parse or validate each match
            parsed_matches = {}
            for match_key, match_data in guard.matches.items():
                print("\n\n match data -->", match_data)
                # _parse_match may raise various exceptions if the data is invalid
                parsed_matches[match_key] = self.parse_match_obj(match_key, match_data)

            # Create and return a new Guard object or update the existing one
            return Guard(
                name=guard.name,
                matches=parsed_matches,
                threshold=threshold,
                count_threshold=guard.count_threshold or 0
            )

        except (KeyError, GuardThresholdParsingError, ValueError) as e:
            # Catch whatever errors might arise (KeyError for missing fields, etc.)
            raise GuardConfigValidationError(f"Failed to parse Guard object: {e}") from e
