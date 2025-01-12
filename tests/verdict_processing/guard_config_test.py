from pathlib import Path
from textwrap import dedent
from typing import Dict

import pytest
import yaml

from acuvity.verdict_processing.constants import analyzer_id_name_map
from acuvity.verdict_processing.models.errors import (
    GuardConfigError,
    ThresholdParsingError,
)
from acuvity.config.guard_config import (
    ComparisonOperator,
    GuardConfig,
)


def create_test_config(tmp_path: Path, content: str) -> Path:
    """Helper to create test config file"""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(dedent(content))
    return config_path

class TestGuardConfig:
    @pytest.fixture
    def analyzer_map(self) -> Dict[str, str]:
        return analyzer_id_name_map

    @pytest.fixture
    def parser(self, analyzer_map):
        return GuardConfig(analyzer_map)

    def test_parse_threshold(self, parser):
        threshold = parser._parse_threshold('>= 0.8')
        assert threshold.value == 0.8
        assert threshold.operator == ComparisonOperator.GREATER_EQUAL

        with pytest.raises(ThresholdParsingError):
            parser._parse_threshold('invalid')

    def test_parse_pii_detector(self, parser, tmp_path):
        config_yaml = """
        name: "pii_detector"
        count_threshold: 3
        matches:
          email:
            threshold: ">= 0.8"
            redact: true
            count_threshold: 2
          person:
            threshold: ">= 1.0"
            redact: true
          location:
        """

        config_path = create_test_config(tmp_path, config_yaml)
        configs = parser.parse_config(config_path)

        assert len(configs) == 1
        config = configs[0]

        assert config.name == 'pii_detector'
        assert config.analyzer_id == 'en-text-ner-detector'
        assert config.count_threshold == 3

        # Check email match
        email_match = config.matches['email']
        assert email_match.threshold.value == 0.8
        assert email_match.threshold.operator == ComparisonOperator.GREATER_EQUAL
        assert email_match.redact is True
        assert email_match.count_threshold == 2

        # Check person match
        person_match = config.matches['person']
        assert person_match.threshold.value == 1.0
        assert person_match.redact is True

         # Check location match
        person_match = config.matches['location']
        assert person_match.threshold.value == 0.0
        assert person_match.threshold.operator == ComparisonOperator.GREATER_THAN
        assert person_match.redact is False

    def test_parse_content_safety(self, parser: GuardConfig, tmp_path):
        config_yaml = """
        guardrails:
          - name: "prompt_injection"
            threshold: ">= 0.7"
          - name: "toxicity"
          - name: "jail_break"
            threshold: ">= 1.0"
        """

        config_path = create_test_config(tmp_path, config_yaml)
        configs = parser.parse_config(config_path)

        assert len(configs) == 3

        analyzers = parser.analyzer_ids
        assert len(analyzers) == 3
        # Check simple guards
        simple_guards = parser.simple_guards
        assert len(simple_guards) == 3

        # Check prompt injection config
        pi_config = next(c for c in configs if c.name == 'prompt_injection')
        assert pi_config.analyzer_id == 'en-text-prompt_injection-detector'
        assert pi_config.threshold.value == 0.7

        # Check toxicity config
        tox_config = next(c for c in configs if c.name == 'toxicity')
        assert tox_config.analyzer_id == 'en-text-toxicity-detector'
        assert tox_config.threshold.value == 0.0

        # Check jailbreak config
        jb_config = next(c for c in configs if c.name == 'jail_break')
        assert jb_config.analyzer_id == 'en-text-jailbreak-detector'
        assert jb_config.threshold.value == 1.0

    def test_invalid_yaml(self, parser, tmp_path):
        config_yaml = """
        invalid:
          - yaml: [
        """

        config_path = create_test_config(tmp_path, config_yaml)
        with pytest.raises(GuardConfigError):
            parser.parse_config(config_path)

    def test_unknown_analyzer(self, parser, tmp_path):
        config_yaml = """
        name: "unknown_analyzer"
        threshold: ">= 0.8"
        """

        config_path = create_test_config(tmp_path, config_yaml)
        with pytest.raises(GuardConfigError):
            parser.parse_config(config_path)

    def test_keyword_guard(self, parser: GuardConfig, tmp_path: Path):
        config_yaml = '''
        guardrails:
          - name: "keyword_detector"
            matches:
              testing:
                threshold: ">= 0.8"
                redact: true
          - name: "pii_detector"
            matches:
              email:
                threshold: ">= 0.8"
                redact: true
          - name: "prompt_injection"
            threshold: ">= 0.7"
          - name: "toxicity"
            threshold: ">= 0.9"
        '''

        config_path = create_test_config(tmp_path, config_yaml)
        parser.parse_config(config_path)

        print("total guards ", len(parser.simple_guards))
        # Check match guards
        match_guards = parser.match_guards
        assert len(match_guards) == 2

        assert len(parser.keywords) == 1
        redact_keys = parser.redaction_keys
        assert len(redact_keys) == 2


    def test_guard_categorization(self, parser: GuardConfig, tmp_path: Path):
        config_yaml = '''
        guardrails:
          - name: "pii_detector"
            matches:
              email:
                threshold: ">= 0.8"
                redact: true
          - name: "prompt_injection"
            threshold: ">= 0.7"
          - name: "toxicity"
            threshold: ">= 0.9"
        '''

        config_path = create_test_config(tmp_path, config_yaml)
        parser.parse_config(config_path)

        # Check match guards
        match_guards = parser.match_guards
        assert len(match_guards) == 1

        redact_keys = parser.redaction_keys
        assert len(redact_keys) == 1

        assert match_guards[0].name == "pii_detector"
        assert "email" in match_guards[0].matches

        # Check simple guards
        simple_guards = parser.simple_guards
        assert len(simple_guards) == 2
        assert {g.name for g in simple_guards} == {"prompt_injection", "toxicity"}
        assert all(not g.matches for g in simple_guards)

    def test_invalid_threshold_format(self, parser, tmp_path):
        config_yaml = """
        name: "pii_detector"
        threshold: "invalid"
        """

        config_path = create_test_config(tmp_path, config_yaml)

        with pytest.raises(GuardConfigError):
            parser.parse_config(config_path)

if __name__ == '__main__':
    pytest.main([__file__])
