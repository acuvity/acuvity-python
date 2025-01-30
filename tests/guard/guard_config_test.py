import tempfile
from pathlib import Path
from textwrap import dedent
from typing import List

import pytest
import yaml

from acuvity.guard import Guard, GuardConfig
from acuvity.guard.constants import GuardName
from acuvity.guard.errors import GuardConfigValidationError
from acuvity.guard.threshold import Threshold


def create_test_config(tmp_path: Path, content: str) -> Path:
    """Helper to create test config file"""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(dedent(content))
    return config_path

# Sample configuration for testing
SAMPLE_CONFIG = {
    "name": "prompt_injection",
    "threshold": "> 0.5"
}

@pytest.fixture
def sample_guard() -> Guard:
    """Create a sample Guard object for testing"""
    return Guard(
        name=GuardName.PROMPT_INJECTION,
        matches={},
        threshold=Threshold("> 0.5"),
        count_threshold=0
    )

@pytest.fixture
def invalid_threshold_guard() -> Guard:
    """Create a sample Guard object for testing"""
    return Guard(
        name=GuardName.PROMPT_INJECTION,
        matches={},
        threshold=Threshold("> 4444"),
        count_threshold=0
    )

def test_init_with_none():
    """Test initialization with None (default configuration)"""
    config = GuardConfig(None)

    # Verify default configuration excludes keyword detector
    assert len(config.guard_names) > 0
    assert GuardName.KEYWORD_DETECTOR not in config.guard_names
    assert all(isinstance(guard, Guard) for guard in config.guards)

def test_init_with_dict():
    """Test initialization with dictionary configuration"""
    config = GuardConfig(SAMPLE_CONFIG)

    assert len(config.guards) == 1
    guard = config.guards[0]
    assert guard.name == GuardName.PROMPT_INJECTION
    assert guard.threshold == Threshold("> 0.5")
    assert guard.matches == {}

def test_init_with_yaml_str(tmp_path):
    """Test initialization with YAML file path as string"""
    # Create temporary YAML file
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(SAMPLE_CONFIG, f)

    config = GuardConfig(str(config_path))

    assert len(config.guards) == 1
    guard = config.guards[0]
    assert guard.name == GuardName.PROMPT_INJECTION
    assert guard.threshold == Threshold("> 0.5")

def test_init_with_yaml_path(tmp_path):
    """Test initialization with YAML file path as Path object"""
    # Create temporary YAML file
    config_path = tmp_path / "config.yaml"
    with open(config_path, 'w', encoding='utf-8') as f:
        yaml.dump(SAMPLE_CONFIG, f)

    config = GuardConfig(Path(config_path))

    assert len(config.guards) == 1
    guard = config.guards[0]
    assert guard.name == GuardName.PROMPT_INJECTION
    assert guard.threshold == Threshold("> 0.5")

def test_init_with_guard_list(sample_guard):
    """Test initialization with list of Guard objects"""
    guards = [sample_guard]
    config = GuardConfig(guards)

    assert len(config.guards) == 1
    guard = config.guards[0]
    assert guard.name == GuardName.PROMPT_INJECTION
    assert guard.threshold == Threshold("> 0.5")
    assert guard.matches == {}

def test_guard_with_invalid_threshold():
    """Test that Guard creation fails with invalid threshold"""
    with pytest.raises(GuardConfigValidationError) as exc_info:
        Guard(
            name=GuardName.PROMPT_INJECTION,
            matches={},
            threshold=Threshold("> 4444"),  # Exception happens here
            count_threshold=0
        )

    assert str(exc_info.value) == "Invalid threshold value should be between 0-1"
