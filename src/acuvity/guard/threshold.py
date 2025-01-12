from dataclasses import dataclass

from .constants import ComparisonOperator
from .errors import ThresholdParsingError


@dataclass(frozen=False)
class Threshold:
    def __init__(self, threshold_str: str):
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
            self.value = float(value_str)

            try:
                self.operator = ComparisonOperator(operator_str)
            except ValueError as e :
                raise ThresholdParsingError(f"Invalid operator: {operator_str}") from e

        except ValueError as e:
            raise ThresholdParsingError("Invalid threshold format") from e

    def __str__(self) -> str:
        return f"{self.operator.value} {self.value}"

    def compare(self, value: float) -> bool:
        """
        Compare a value against a threshold.

        Args:
            threshold: Threshold object containing operator and value
            value: Value to compare against threshold

        Returns:
            True if value meets threshold criteria, False otherwise
        """
        if self.operator == ComparisonOperator.GREATER_THAN:
            return value > self.value
        if self.operator == ComparisonOperator.GREATER_EQUAL:
            return value >= self.value
        if self.operator == ComparisonOperator.EQUAL:
            return value == self.value
        if self.operator == ComparisonOperator.LESS_EQUAL:
            return value <= self.value
        if self.operator == ComparisonOperator.LESS_THAN:
            return value < self.value
        return False
