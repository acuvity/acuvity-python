from acuvity import models
from acuvity.apexextend import ApexExtended
from acuvity.types import OptionalNullable, UNSET
from .httpclient import AsyncHttpClient, HttpClient
from .utils.logger import Logger
from .utils.retries import RetryConfig
from typing import Callable, Dict, Optional, Union
from .basesdk import BaseSDK
from .apexextend import ApexExtended

class Acuvity(BaseSDK):
    apex: ApexExtended

    # pylint: disable=super-init-not-called
    def __init__(
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
        pass
