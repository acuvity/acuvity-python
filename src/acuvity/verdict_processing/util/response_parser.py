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
        if not path or not isinstance(path, str):
            raise ValidationError("Invalid path: path must be a non-empty string")

        try:
            current = response
            for key in path.split('.'):
                # Try to convert to integer for array indexing
                if isinstance(current, list):
                    try:
                        index = int(key)
                        current = current[index]
                    except ValueError as e:
                        raise ValidationError(f"Invalid array index: {key}") from e
                    except IndexError as e:
                        raise ValidationError(f"Array index out of bounds at: {path}") from e
                else:
                    if key not in current:
                        raise ValidationError(f"Path not found in response {path}")
                    current = current[key]

            return current
        except KeyError as e:
            raise ValidationError(f"Path not found in response {path}") from e
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
