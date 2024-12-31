"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from ._hooks import SDKHooks
from .httpclient import AsyncHttpClient, HttpClient
from .utils import Logger, RetryConfig, remove_suffix
from acuvity import models
from acuvity.types import OptionalNullable, UNSET
from dataclasses import dataclass, field
from pydantic import Field
from typing import Callable, Dict, List, Optional, Tuple, Union


SERVERS = [
    "https://{apex_domain}:{apex_port}",
    # The Apex API server which is specific to every organization.
    # The apex_domain and apex_port variables can be determined by a call to
    # the well-known Apex info endpoint on the backend.
]
"""Contains the list of servers available to the SDK"""


@dataclass
class SDKConfiguration:
    client: HttpClient
    async_client: AsyncHttpClient
    debug_logger: Logger
    security: Optional[Union[models.Security, Callable[[], models.Security]]] = None
    server_url: Optional[str] = ""
    server_idx: Optional[int] = 0
    server_defaults: List[Dict[str, str]] = field(default_factory=List)
    language: str = "python"
    openapi_doc_version: str = "1.0"
    sdk_version: str = "0.3.0"
    gen_version: str = "2.484.0"
    user_agent: str = "speakeasy-sdk/python 0.3.0 2.484.0 1.0 acuvity"
    retry_config: OptionalNullable[RetryConfig] = Field(default_factory=lambda: UNSET)
    timeout_ms: Optional[int] = None

    def __post_init__(self):
        self._hooks = SDKHooks()

    def get_server_details(self) -> Tuple[str, Dict[str, str]]:
        if self.server_url is not None and self.server_url:
            return remove_suffix(self.server_url, "/"), {}
        if self.server_idx is None:
            self.server_idx = 0

        return SERVERS[self.server_idx], self.server_defaults[self.server_idx]

    def get_hooks(self) -> SDKHooks:
        return self._hooks
