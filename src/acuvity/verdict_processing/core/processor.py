from pathlib import Path
from typing import Any, Dict, Union

from ...utils.logger import get_default_logger
from ..constants import analyzer_id_name_map
from ..models.guard_config import GuardConfigParser
from ..models.result import ProcessorResult
from ..util.response_parser import ResponseParser
from ..util.threshold_helper import ThresholdHelper
from .check_builder import CheckBuilder
from .guard_processor import CheckEvaluator, GuardProcessor

logger = get_default_logger()

class VerdictProcessor:
    """
    Main orchestrator for verdict processing.
    Provides interfaces for guard configuration processing.
    """

    def __init__(self, guard_config: Union[str, Path, Dict]):
        """
        Initialize the processor with all its components.
        """
        self._parser = ResponseParser()
        self._threshold_helper = ThresholdHelper()

        # Initialize components
        self._evaluator = CheckEvaluator(self._parser, self._threshold_helper)
        self._guard_processor = GuardProcessor(self._evaluator, self._threshold_helper)

        guard_config_parser = GuardConfigParser(analyzer_id_name_map)
        guard_config_parser.parse_config(guard_config)


    # def check(self, path: str) -> CheckBuilder:
    #     """
    #     Start a fluent check interface for direct checks.
    #     """
    #     return CheckBuilder(self._evaluator, self._response, path)

    def get_verdict_from_guardconfig(
        self,
        response: Dict[str, Any]
    ) -> ProcessorResult:
        """
        Process a complete guard configuration.
        """
        # Validate response structure
        self._parser.validate_response(response)
        return self._guard_processor.process_config(config)
