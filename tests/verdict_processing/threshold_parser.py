# tests/verdict_processing/utils/test_threshold_helper.py
import pytest

from acuvity.verdict_processing.constants import ThresholdOperator
from acuvity.verdict_processing.models.errors import ValidationError
from acuvity.verdict_processing.util.threshold_helper import ThresholdHelper


class TestThresholdHelper:
    """Test suite for ThresholdHelper class."""

    @pytest.mark.parametrize("input_str, expected_value, expected_operator", [
        (">= 0.7", 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL),
        ("> 0.7", 0.7, ThresholdOperator.GREATER_THAN),
        ("<= 0.7", 0.7, ThresholdOperator.LESS_THAN_OR_EQUAL),
        ("< 0.7", 0.7, ThresholdOperator.LESS_THAN),
        ("= 0.7", 0.7, ThresholdOperator.EQUAL),
        ("0.7", 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # Default operator
        ("  >= 0.7  ", 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # With whitespace
        (">=0.7", 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # No space
        (">= -0.7", -0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # Negative numbers
        (">= 1", 1.0, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # Integer
        ("1.0", 1.0, ThresholdOperator.GREATER_THAN_OR_EQUAL),  # Just number
    ])
    def test_parse_threshold_valid_inputs(self, input_str, expected_value, expected_operator):
        """Test parsing various valid threshold strings."""
        value, operator = ThresholdHelper.parse_threshold(input_str)
        assert value == expected_value
        assert operator == expected_operator

    @pytest.mark.parametrize("invalid_input", [
        "",  # Empty string
        "  ",  # Only whitespace
        ">= abc",  # Invalid number
        "invalid",  # Invalid format
        ">=",  # Missing value
        ">>= 0.7",  # Invalid operator
        None,  # None input
        "> > 0.7",  # Double operator
        "0.7 >=",  # Reversed format
        ">=>=0.7",  # Double operator
    ])
    def test_parse_threshold_invalid_inputs(self, invalid_input):
        """Test parsing invalid threshold strings."""
        with pytest.raises(ValidationError):
            ThresholdHelper.parse_threshold(invalid_input)

    @pytest.mark.parametrize("value, threshold, operator, expected", [
        # Greater than tests
        (0.8, 0.7, ThresholdOperator.GREATER_THAN, True),
        (0.7, 0.7, ThresholdOperator.GREATER_THAN, False),
        (0.6, 0.7, ThresholdOperator.GREATER_THAN, False),

        # Greater than or equal tests
        (0.8, 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL, True),
        (0.7, 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL, True),
        (0.6, 0.7, ThresholdOperator.GREATER_THAN_OR_EQUAL, False),

        # Less than tests
        (0.6, 0.7, ThresholdOperator.LESS_THAN, True),
        (0.7, 0.7, ThresholdOperator.LESS_THAN, False),
        (0.8, 0.7, ThresholdOperator.LESS_THAN, False),

        # Less than or equal tests
        (0.6, 0.7, ThresholdOperator.LESS_THAN_OR_EQUAL, True),
        (0.7, 0.7, ThresholdOperator.LESS_THAN_OR_EQUAL, True),
        (0.8, 0.7, ThresholdOperator.LESS_THAN_OR_EQUAL, False),

        # Equal tests
        (0.7, 0.7, ThresholdOperator.EQUAL, True),
        (0.70000001, 0.7, ThresholdOperator.EQUAL, False),  # Float comparison with epsilon
        (0.71, 0.7, ThresholdOperator.EQUAL, False),

        # Integer comparisons
        (1, 1, ThresholdOperator.EQUAL, True),
        (1.0, 1, ThresholdOperator.EQUAL, True),

        # Zero comparisons
        (0, 0, ThresholdOperator.EQUAL, True),
        (0.1, 0, ThresholdOperator.GREATER_THAN, True),
        (-0.1, 0, ThresholdOperator.LESS_THAN, True),

        # Negative number comparisons
        (-0.7, -0.8, ThresholdOperator.GREATER_THAN, True),
        (-0.9, -0.8, ThresholdOperator.LESS_THAN, True),
    ])
    def test_compare_valid_cases(self, value, threshold, operator, expected):
        """Test various valid comparison cases."""
        assert ThresholdHelper.compare(value, threshold, operator) == expected

    @pytest.mark.parametrize("value, threshold, operator", [
        ("invalid", 0.7, ThresholdOperator.GREATER_THAN),  # Invalid value
        (0.7, "invalid", ThresholdOperator.GREATER_THAN),  # Invalid threshold
        (0.7, 0.7, "invalid"),  # Invalid operator
        (None, 0.7, ThresholdOperator.GREATER_THAN),  # None value
        (0.7, None, ThresholdOperator.GREATER_THAN),  # None threshold
        ({}, 0.7, ThresholdOperator.GREATER_THAN),  # Invalid type
        ([], 0.7, ThresholdOperator.GREATER_THAN),  # Invalid type
    ])
    def test_compare_invalid_cases(self, value, threshold, operator):
        """Test various invalid comparison cases."""
        with pytest.raises((ValidationError, TypeError)):
            ThresholdHelper.compare(value, threshold, operator)

    def test_end_to_end_threshold_parsing_and_comparison(self):
        """Test complete flow from string parsing to comparison."""
        # Parse threshold string
        threshold_str = ">= 0.7"
        value, operator = ThresholdHelper.parse_threshold(threshold_str)

        # Use parsed values for comparison
        assert value == 0.7
        assert operator == ThresholdOperator.GREATER_THAN_OR_EQUAL

        # Test actual comparison
        assert ThresholdHelper.compare(0.8, value, operator) is True
        assert ThresholdHelper.compare(0.6, value, operator) is False
        assert ThresholdHelper.compare(0.7, value, operator) is True
