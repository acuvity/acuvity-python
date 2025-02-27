import pytest
import logging
import os
from acuvity import Acuvity, Security
from acuvity.utils import BackoffStrategy, RetryConfig


class TestAcuvityObject:
    @pytest.fixture(autouse=True)
    def load_setup_fixtures(self, get_token):
        self.token = get_token

    def test_correct_token(self):
        with Acuvity(security=Security(token=self.token)) as c:
            result = c.apex.scan("test message")
            assert result

    def test_empty_token(self):
        with pytest.raises(ValueError, match="No token provided"):
            Acuvity(security=Security(token=""))

    def test_custom_retries(self):
        with Acuvity(
            retry_config=RetryConfig("backoff", BackoffStrategy(1, 5, 1.1, 10), False),
            security=Security(token=self.token),
        ) as c:
            assert (
                c.sdk_configuration.retry_config
            ), f"Custom retry config not loaded {c.sdk_configuration.retry_config}"

    def test_debug(self, set_acuvity_debug):
        with Acuvity(security=Security(token=self.token)) as c:
            acuvity_logger = c.sdk_configuration.debug_logger
            assert (
                type(acuvity_logger) == logging.Logger and acuvity_logger.level == 0
            ), f"Debug logging was not enabled"
