from typing import Any, Dict, Union

from ..models.errors import ValidationError


class ResponseParser:
    """Helper class for parsing and accessing response data."""

    @staticmethod
    def get_value(response: Dict[str, Any], path: str) -> Union[float, int, str]:
        """
        Get a value from the response using a dot-notation path.

        Args:
            response: The response dictionary
            path: Path to the value (e.g., "exploits.prompt_injection")

        Returns:
            The value at the specified path

        Raises:
            ValidationError: If path is invalid or value doesn't exist
        """
        try:
            current = response
            for key in path.split('.'):
                current = current[key]

            if not isinstance(current, (int, float, str)):
                raise ValidationError(f"Value at path {path} is not a numeric or string type")

            return current
        except KeyError as e:
            raise ValidationError(f"Path {path} not found in response") from e
        except Exception as e:
            raise ValidationError(f"Error accessing path {path}: {str(e)}") from e

    @staticmethod
    def validate_response(response: Dict[str, Any]) -> None:
        """
        Validate the basic structure of a response.

        Args:
            response: The response dictionary to validate

        Raises:
            ValidationError: If response is invalid
        """
        if not isinstance(response, dict):
            raise ValidationError("Response must be a dictionary")

        required_sections = ['exploits', 'modalities', 'languages']
        missing = [section for section in required_sections if section not in response]

        if missing:
            raise ValidationError(f"Response missing required sections: {', '.join(missing)}")
