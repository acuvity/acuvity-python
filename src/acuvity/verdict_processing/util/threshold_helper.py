from typing import Tuple, Union

from ..constants import ThresholdOperator
from ..models.errors import ValidationError


class ThresholdHelper:
    """Helper class for threshold comparisons."""

    @staticmethod
    def compare(value: Union[int, float, str], threshold: float, operator: ThresholdOperator) -> bool:
        """
        Compare a value against a threshold using the specified operator.

        Args:
            value: The value to compare (will be converted to float)
            threshold: The threshold to compare against
            operator: The comparison operator to use

        Returns:
            bool: True if the comparison is satisfied
        """
        try:
            numeric_value = float(value)
        except (TypeError, ValueError) as e:
            raise ValidationError(f"Cannot convert value {value} to float") from e

        comparison_ops = {
            ThresholdOperator.GREATER_THAN: lambda x, y: x > y,
            ThresholdOperator.GREATER_THAN_OR_EQUAL: lambda x, y: x >= y,
            ThresholdOperator.LESS_THAN: lambda x, y: x < y,
            ThresholdOperator.LESS_THAN_OR_EQUAL: lambda x, y: x <= y,
            ThresholdOperator.EQUAL: lambda x, y: abs(x - y) < 1e-9
        }

        return comparison_ops[operator](numeric_value, threshold)

    @staticmethod
    def parse_threshold(threshold_str: Union[str, float]) -> Tuple[float, ThresholdOperator]:
        """
        Parse threshold string into value and operator.

        Args:
            threshold_str: String like '>= 0.7' or '0.7' or float value

        Returns:
            Tuple of (threshold_value, threshold_operator)
        """
        # Handle numeric input
        if isinstance(threshold_str, (int, float)):
            return float(threshold_str), ThresholdOperator.GREATER_THAN_OR_EQUAL

        threshold_str = str(threshold_str).strip()

        # Mapping of string representations to operators
        operator_map = {
            '>=': ThresholdOperator.GREATER_THAN_OR_EQUAL,
            '>': ThresholdOperator.GREATER_THAN,
            '<=': ThresholdOperator.LESS_THAN_OR_EQUAL,
            '<': ThresholdOperator.LESS_THAN,
            '=': ThresholdOperator.EQUAL
        }

        # Try to find operator in string
        found_operator = None
        for op_str, operator in operator_map.items():
            if threshold_str.startswith(op_str):
                found_operator = operator
                threshold_str = threshold_str[len(op_str):].strip()
                break

        # If no operator found, default to GREATER_THAN_OR_EQUAL
        if found_operator is None:
            found_operator = ThresholdOperator.GREATER_THAN_OR_EQUAL

        try:
            threshold_value = float(threshold_str)
        except ValueError as e:
            raise ValidationError(f"Invalid threshold value: {threshold_str}") from e

        return threshold_value, found_operator
