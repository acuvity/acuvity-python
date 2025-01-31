# pylint: disable=protected-access

from acuvity import models
from acuvity.apexdiscovery import discover_apex
from acuvity.apexextend import ApexExtended
from acuvity.sdk import Acuvity
from acuvity.types import OptionalNullable, UNSET
from .httpclient import AsyncHttpClient, HttpClient
from .utils.logger import Logger
from .utils.retries import RetryConfig
from typing import Callable, Dict, Optional, Union
import httpx

# Save the original __init__ reference
__original_init__ = Acuvity.__init__

# Define the new __init__ method
def __patched_init__(
    self,
    security: Optional[
        Union[models.Security, Callable[[], models.Security]]
    ] = None,
    apex_domain: Optional[str] = None,
    apex_port: Optional[str] = None,
    server_idx: Optional[int] = None,
    server_url: Optional[str] = None,
    url_params: Optional[Dict[str, str]] = None,
    client: Optional[HttpClient] = None,
    async_client: Optional[AsyncHttpClient] = None,
    retry_config: OptionalNullable[RetryConfig] = UNSET,
    timeout_ms: Optional[int] = None,
    debug_logger: Optional[Logger] = None,
) -> None:
    r"""Instantiates the SDK configuring it with the provided parameters.

    :param security: The security details required for authentication
    :param apex_domain: Allows setting the apex_domain variable for url substitution
    :param apex_port: Allows setting the apex_port variable for url substitution
    :param server_idx: The index of the server to use for all methods
    :param server_url: The server URL to use for all methods
    :param url_params: Parameters to optionally template the server URL with
    :param client: The HTTP client to use for all synchronous methods
    :param async_client: The Async HTTP client to use for all asynchronous methods
    :param retry_config: The retry configuration to use for all supported methods
    :param timeout_ms: Optional request timeout applied to each operation in milliseconds
    """
    if client is None:
        client = httpx.Client()

    assert issubclass(
        type(client), HttpClient
    ), "The provided client must implement the HttpClient protocol."

    apex_domain, apex_port = discover_apex(
        client=client,
        server_url=server_url,
        security=security,
        apex_domain=apex_domain,
        apex_port=apex_port,
    )

    # Call the original __init__ using super
    __original_init__(
        self,
        security=security,
        apex_domain=apex_domain,
        apex_port=apex_port,
        server_idx=server_idx,
        server_url=server_url,
        url_params=url_params,
        client=client,
        async_client=async_client,
        retry_config=retry_config,
        timeout_ms=timeout_ms,
        debug_logger=debug_logger,
    )

# Define the new _init_sdks method
def __patched_init_sdks(self):
    self.apex = ApexExtended(self.sdk_configuration)

# Monkey-patch the __init__ and _init_sdks methods
setattr(Acuvity, "__init__", __patched_init__)
setattr(Acuvity, "_init_sdks", __patched_init_sdks)
