from dataclasses import dataclass
from typing import Optional

from ..constants import ComparisonOperator
from ..models.errors import ThresholdParsingError


@dataclass(frozen=True)
class Threshold:
    """Immutable threshold configuration"""
    value: float
    operator: ComparisonOperator

    def __str__(self) -> str:
        return f"{self.operator.value} {self.value}"

class ThresholdHelper:
    """Helper class for parsing and comparing thresholds"""

    @staticmethod
    def parse_threshold(threshold_str: str) -> Optional[Threshold]:
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
            except ValueError as e :
                raise ThresholdParsingError(f"Invalid operator: {operator_str}") from e

            return Threshold(value=value, operator=operator)

        except ValueError as e:
            raise ThresholdParsingError("Invalid threshold format") from e

    @staticmethod
    def compare(threshold: Threshold, value: float) -> bool:
        """
        Compare a value against a threshold.

        Args:
            threshold: Threshold object containing operator and value
            value: Value to compare against threshold

        Returns:
            True if value meets threshold criteria, False otherwise
        """
        if threshold.operator == ComparisonOperator.GREATER_THAN:
            return value > threshold.value
        if threshold.operator == ComparisonOperator.GREATER_EQUAL:
            return value >= threshold.value
        if threshold.operator == ComparisonOperator.EQUAL:
            return value == threshold.value
        if threshold.operator == ComparisonOperator.LESS_EQUAL:
            return value <= threshold.value
        if threshold.operator == ComparisonOperator.LESS_THAN:
            return value < threshold.value
        return False
