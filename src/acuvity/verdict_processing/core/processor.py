from typing import Any, Dict, Union

from ...utils.logger import get_default_logger
from ..models.config import ProcessorConfig
from ..models.result import ProcessorResult
from ..util.response_parser import ResponseParser
from ..util.threshold_helper import ThresholdHelper
from .check_builder import CheckBuilder
from .evaluator import CheckEvaluator
from .guard_processor import GuardProcessor

logger = get_default_logger()

class VerdictProcessor:
    """
    Main orchestrator for verdict processing.
    Provides interfaces for both direct checks and guard configuration processing.
    """

    def __init__(self, response: Dict[str, Any]):
        """
        Initialize the processor with all its components.
        """
        self._response = response
        self._parser = ResponseParser()
        self._threshold_helper = ThresholdHelper()

        # Initialize components
        self._evaluator = CheckEvaluator(self._parser, self._threshold_helper)
        self._guard_processor = GuardProcessor(self._response, self._evaluator, self._threshold_helper)

        # Validate response structure
        self._parser.validate_response(response)

    def check(self, path: str) -> CheckBuilder:
        """
        Start a fluent check interface for direct checks.
        """
        return CheckBuilder(self._evaluator, self._response, path)

    def get_verdict_from_guardconfig(
        self,
        config: Union[Dict[str, Any], ProcessorConfig]
    ) -> ProcessorResult:
        """
        Process a complete guard configuration.
        """
        return self._guard_processor.process_config(config)
