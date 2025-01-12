from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from ..verdict_processing.constants import ComparisonOperator, analyzer_id_name_map
from ..verdict_processing.util.threshold_helper import Threshold
from ..verdict_processing.models.errors import ConfigValidationError, GuardConfigError, ThresholdParsingError


@dataclass(frozen=True)
class Match:
    """Immutable match configuration"""
    threshold: Optional[Threshold] = None
    redact: bool = False
    count_threshold: Optional[int] = None

@dataclass(frozen=True)
class Guard:
    """Immutable guard configuration"""
    name: str
    analyzer_id: str
    matches: Dict[str, Match]
    threshold: Optional[Threshold] = None
    count_threshold: Optional[int] = None

class GuardConfig:
    """
    Parser for guard configuration files.

    This class handles parsing of guard configuration files in YAML format,
    validating their contents, and converting between analyzer names and IDs.

    The parser handles two types of guards:
    1. Match Guards: Guards with a 'matches' section (e.g., pii_detector)
    2. Simple Guards: Guards without matches (e.g., prompt_injection, toxicity)
    """

    DEFAULT_THRESHOLD = Threshold(0.0, ComparisonOperator.GREATER_THAN)
    def __init__(self, config: Union[str, Path, Dict]):
        self._parsed_guards: List[Guard] = []
        """
        Initialize parser with analyzer mapping.

        Args:
            analyzer_id_name_map: Mapping from analyzer IDs to names
        """
        self.analyzer_id_name_map = analyzer_id_name_map
        self.analyzer_name_id_map = {v: k for k, v in analyzer_id_name_map.items()}
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

    def _parse_config(self, config: Union[str, Path, Dict]) -> List[Guard]:
        """
        Parse guard configuration from file or dictionary.

        Args:
            config: Path to YAML file or dictionary containing configuration

        Returns:
            List of parsed Guard objects

        Raises:
            GuardConfigError: If configuration is invalid
        """
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

    def _validate_guard(self, guard: Dict) -> bool:
        """
        Validate individual guard configuration.

        Args:
            guard: Guard configuration dictionary

        Returns:
            True if guard is valid

        Raises:
            ConfigValidationError: If guard configuration is invalid
        """
        if not isinstance(guard, dict):
            raise ConfigValidationError("Guard must be a dictionary")

        if 'name' not in guard:
            raise ConfigValidationError("Guard must have a name")

        if guard['name'] not in self.analyzer_name_id_map:
            raise ConfigValidationError(f"Guard name not present {guard['name']}")

        return True

    def _parse_threshold(self, threshold_str: str) -> Optional[Threshold]:
        """
        Parse threshold string into Threshold object.

        Args:
            threshold_str: Threshold string (e.g. '>= 0.8')

        Returns:
            Threshold object or None if parsing fails

        Raises:
            ThresholdParsingError: If threshold format is invalid
        """
        try:
            operator_str, value_str = threshold_str.split()
            value = float(value_str)

            try:
                operator = ComparisonOperator(operator_str)
            except ValueError as e:
                raise ThresholdParsingError(f"Invalid operator: {operator_str}") from e

            return Threshold(value=value, operator=operator)

        except ValueError as e:
            raise ThresholdParsingError(f"Invalid threshold format: {e}") from e

    def _parse_match(self, match_key: str, match_data: Dict) -> Match:
        """
        Parse match configuration.

        Args:
            match_key: Key identifying the match
            match_data: Match configuration dictionary

        Returns:
            Match object
        """
        threshold = self.DEFAULT_THRESHOLD
        if match_data and 'threshold' in match_data:
            try:
                threshold = self._parse_threshold(match_data['threshold'])
            except ThresholdParsingError as e:
                raise ThresholdParsingError(f"Invalid threshold for match {match_key}") from e

            return Match(
                threshold=threshold,
                redact=match_data.get('redact', False),
                count_threshold=match_data.get('count_threshold')
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
    def simple_guards(self) -> List[Guard]:
        """
        Returns list of guard configurations without match patterns.

        Returns:
            List of Guard objects that don't have 'matches' section
        """
        return [guard for guard in self._parsed_guards
                if not guard.matches]

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

    @property
    def analyzer_ids(self) -> List[str]:
        """
        Returns the list of all analyzer_ids that can be passed to the scan API
        """
        ids = []
        for g in self._parsed_guards:
            ids.append(g.analyzer_id)
        return ids


    def _parse_guard(self, guard: Dict) -> Guard:
        """
        Parse individual guard configuration.

        Args:
            guard: Guard configuration dictionary

        Returns:
            Guard object

        Raises:
            ConfigValidationError: If guard configuration is invalid
        """
        name = guard['name']
        analyzer_id = self.analyzer_name_id_map[name]

        # Parse top-level threshold
        threshold = self.DEFAULT_THRESHOLD
        if 'threshold' in guard:
            try:
                threshold = self._parse_threshold(guard['threshold'])
            except ThresholdParsingError as e:
                raise e
        else:
            threshold = self.DEFAULT_THRESHOLD

        # Parse matches
        matches = {}
        for match_key, match_data in guard.get('matches', {}).items():
            matches[match_key] = self._parse_match(match_key, match_data)

        return Guard(
            name=name,
            analyzer_id=analyzer_id,
            matches=matches,
            threshold=threshold,
            count_threshold=guard.get('count_threshold')
        )
