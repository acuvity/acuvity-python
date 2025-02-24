import pytest
import tempfile
from acuvity import Acuvity, Security
import os

SUPPORTED_PLATFORMS = ["dev", "prod", "pre_prod"]


def pytest_addoption(parser):
    parser.addoption(
        "--platform",
        action="store",
        default="",
        type=str,
        help="Specify platform to run against",
    )


def pytest_configure(config):
    config.acuvity_platform = config.getoption("--platform")


@pytest.fixture(scope="class")
def get_token(request):
    platform = request.config.acuvity_platform
    if platform:
        assert platform in SUPPORTED_PLATFORMS
        token = os.getenv(f"APPS_{platform.upper()}_TOKEN", "")
        assert token, f"APPS_{platform.upper()}_TOKEN env variable missing"
    else:
        token = os.getenv(f"ACUVITY_TOKEN", "")
        assert token, "ACUVITY_TOKEN env variable missing"
    return token


@pytest.fixture(scope="class")
def init_apex(get_token):
    with Acuvity(
        security=Security(token=get_token),
    ) as acuvity:
        yield acuvity.apex


@pytest.fixture(scope="class")
def get_guards(init_apex):
    guards = init_apex.list_available_guards()
    return guards


@pytest.fixture(scope="class")
def tmp_test_dir():
    with tempfile.TemporaryDirectory() as tmp_dir_name:
        yield tmp_dir_name


@pytest.fixture(scope="function")
def set_acuvity_debug():
    os.environ["ACUVITY_DEBUG"] = "true"
    yield
    os.environ.pop("ACUVITY_DEBUG", None)
