# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 Acuvity, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import io
import os
import ssl
import httpx
import json
import jwt
import logging
import functools

from .apex_types import ElementalObject, RequestElementalObject, ResponseElementalObject, ElementalError, ExtractionRequest, ScanRequest, ScanResponse, ScanRequestAnonymizationEnum, ScanRequestTypeEnum, ScanExternalUser, Analyzer
from .api_types import ApexInfo
from pydantic import ValidationError

from typing import Any, IO, Iterable, List, Type, Dict, Sequence, Union, Optional, Tuple
from urllib.parse import urlparse
from tenacity import retry, retry_if_exception_type, wait_random_exponential, stop_after_attempt, stop_after_delay

logger = logging.getLogger(__name__)

# msgpack is optional and sits behind a 'msgpack' extra
try:
    import msgpack
    HAVE_MSGPACK = True
except ImportError:
    HAVE_MSGPACK = False


class RequestRetryException(Exception):
    """
    RequestRetryException is thrown by _make_request whenever the HTTP status code of a response indicates that
    the request can and/or should be retried.
    """


class OutdatedLibraryException(Exception):
    """
    OutdatedLibraryException is thrown by _make_request whenever the HTTP status code of a response indicates that
    the library is outdated and should be updated.
    This can happen if the serialized types are out of date and require this library to be updated to receive the latest updates.
    """
    def __init__(self, message: str = "Your 'acuvity' library is outdated. Please update to the latest version."):
        super().__init__(message)


class AcuvityClientException(Exception):
    """
    AcuvityClientException is thrown by the AcuvityClient whenever a known and documented error occurs during the execution of a request.
    This will include an ElementalError object that contains the error message and potentially more information.
    """
    def __init__(self, elemental_error: Union[ElementalError, List[ElementalError]], message: str):
        self.error = elemental_error
        super().__init__(message)


class AcuvityProxyClient:
    """
    AcuvityProxyClient is an initializer for a proxy client that will use the Acuvity Apex to proxy requests.

    It offers an httpx.Client instance which is prepared to proxy requests through the Acuvity Apex service.
    """
    def __init__(
        self,
        *,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
        api_url: Optional[str] = None,
        apex_url: Optional[str] = None,
        apex_cas: Optional[Union[str, os.PathLike, IO[bytes]]] = None,
        retry_max_attempts: int = 10,
        retry_max_wait: int = 300,
    ):
        """
        Initializes a new Acuvity proxy client. At a minimum you need to provide a token, which can get passed through an environment variable.
        The rest of the values can be detected from and/or with the token.

        :param token: the API token to use for authentication. If not provided, it will be detected from the environment variable ACUVITY_TOKEN. If that fails, the initialization fails.
        :param namespace: the namespace to use for the API calls. If not provided, it will be detected from the environment variable ACUVITY_NAMESPACE or it will be derived from the token. If that fails, the initialization fails.
        :param api_url: the URL of the Acuvity API to use. If not provided, it will be detected from the environment variable ACUVITY_API_URL or it will be derived from the token. If that fails, the initialization fails.
        :param apex_url: the URL of the Acuvity Apex service to use. If not provided, it will be detected from the environment variable ACUVITY_APEX_URL or it will be derived from an API call. If that fails, the initialization fails.
        :param apex_cas: the CA certificates to use for the Apex service. If not provided, it will be detected from the well-known Apex info endpoint from the API. If that fails, the initialization fails.
        :param retry_max_attempts: the maximum number of retry attempts to make on failed requests that can be retried. Defaults to 10.
        :param retry_max_wait: the maximum number of seconds to wait for all retry attempts. Defaults to 300 seconds.
        """

        # take the values as is
        self._retry_max_attempts: int = retry_max_attempts
        self._retry_max_wait: int = retry_max_wait

        # we initialize the client early as we might require it to fully initialize our own client
        self.http_client = httpx.Client(
            timeout=httpx.Timeout(timeout=600.0, connect=5.0),
            limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
            follow_redirects=True,
            http2=True,
        )

        # token first, as we potentially need it to detect the other values
        if token is None:
            token = os.getenv("ACUVITY_TOKEN", None)
        if token is None or token == "":
            raise ValueError("no API token provided")
        self.token = token

        try:
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            if "iss" not in decoded_token:
                raise ValueError("token has no 'iss' field")
            if "source" not in decoded_token:
                raise ValueError("token has no 'source' field")
            if "namespace" not in decoded_token["source"]:
                raise ValueError("token has no 'source.namespace' field")
            if "restrictions" not in decoded_token:
                raise ValueError("token has no 'restrictions' field")
            if "namespace" not in decoded_token["restrictions"]:
                raise ValueError("token has no 'restrictions.namespace' field")
        except Exception as e:
            raise ValueError("invalid token provided: " + str(e))

        # API URL next, as we might need to query it
        if api_url is None:
            api_url = os.getenv("ACUVITY_API_URL", None)
        if api_url is None or api_url == "":
            api_url = decoded_token['iss']
        if api_url is None or api_url == "":
            raise ValueError("no API URL provided or detected")
        self.api_url = api_url

        try:
            parsed_url = urlparse(api_url)
            # use hostname as opposed to netloc because we *only* want the domain, and not the domain:port notation
            domain = parsed_url.hostname
            if domain == "":
                raise ValueError("no domain in URL")
            self.api_domain = domain
            self.api_tld_domain = ".".join(domain.split('.')[1:])
            if parsed_url.scheme != "https" and parsed_url.scheme != "http":
                raise ValueError(f"invalid scheme: {parsed_url.scheme}")
        except Exception as e:
            raise ValueError("API URL is not a valid URL: " + str(e))

        # namespace next, as we might need it to query the API as it is a reqired header
        if namespace is None:
            namespace = os.getenv("ACUVITY_NAMESPACE", None)
        if namespace is None or namespace == "":
            namespace = decoded_token["restrictions"]["namespace"]
        if namespace is None or namespace == "":
            raise ValueError("no namespace provided or detected")
        self.namespace = namespace

        # we set the cookie here for the API domain as it might be doing redirects
        # during redirects we lose the headers that we sent during the initial request
        # so it is easier to simply use the cookie to keep the token for all subsequent requests
        # we ensure to limit it in the client here for just the API domain
        self.http_client.cookies.set("x-a3s-token", self.token, domain=self.api_domain)

        # and last but not least, the apex URL which is the service/proxy that provides the APIs
        # that we want to actually use in this client
        if apex_url is None:
            apex_url = os.getenv("ACUVITY_APEX_URL", None)
        if apex_url is not None and apex_url != "":
            # the Apex URL was passed in the constructor
            # this means that we are expecting CA certs to be passed in as well
            if apex_cas is None:
                raise ValueError("you must provide CA certs when you manually provide the Apex URL")
            if isinstance(apex_cas, (str, os.PathLike)):
                with open(apex_cas, 'rb') as f:
                    cas = f.read()
            elif hasattr(apex_cas, 'read'):
                cas = apex_cas.read()
                if not isinstance(cas, bytes):
                    raise ValueError(f"expected bytes while reading from file-like apex_cas object, but got {type(cas)}")
            else:
                raise ValueError(f"invalid type for CA certs: {type(apex_cas)}")
            cas = cas.decode('utf-8')
        elif apex_url is None or apex_url == "":
            try:
                apex_info = self.well_known_apex_info()
                if apex_info.cas is not None and apex_info.cas != "":
                    cas = apex_info.cas
                else:
                    raise ValueError("no CA certs provided by well-known Apex info endpoint")
            except Exception as e:
                raise ValueError("failed to detect apex URL: could not retrieve well-known Apex info") from e
            apex_port = f":{apex_info.port}" if apex_info.port is not None else ""
            apex_url = f"https://{apex_info.url}{apex_port}" if not apex_info.url.startswith(("https://", "http://")) else f"{apex_info.url}{apex_port}"
        self.apex_url = apex_url

        # if the API provided us with Apex CA certs, we're going to recreate the
        # http_client to make use of them.
        sslctx = ssl.create_default_context()
        sslctx.load_verify_locations(cadata=cas)
        self.http_client = httpx.Client(
            timeout=httpx.Timeout(timeout=600.0, connect=5.0),
            limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
            follow_redirects=True,
            http2=True,
            verify=sslctx,
        )
        self.http_client.cookies.set("x-a3s-token", self.token, domain=self.api_domain)

        try:
            parsed_url = urlparse(apex_url)
            # use hostname as opposed to netloc because we *only* want the domain, and not the domain:port notation
            domain = parsed_url.hostname
            if domain == "":
                raise ValueError(f"Apex URL: no domain in URL: {self.apex_url}")
            self.apex_domain = domain
            self.apex_tld_domain = ".".join(domain.split('.')[1:])
            if parsed_url.scheme != "https" and parsed_url.scheme != "http":
                raise ValueError(f"Apex URL: invalid scheme: {parsed_url.scheme}: {self.apex_url}")
        except Exception as e:
            raise ValueError("Apex URL is not a valid URL: " + str(e))

        # again, we are going to set the cookie here for the apex domain
        # this simplifies the request handling as we can always rely on the cookie being set on everything
        # that we sent to the apex - even on redirects
        self.http_client.cookies.set("x-a3s-token", self.token, domain=self.apex_domain)

    def _build_headers(self, method: str, domain: str) -> Dict[str, str]:
        # we always send our namespace
        ret = {
            "X-Namespace": self.namespace,
        }

        # but we only send the token as an Authorization header if there is no cookie set
        # this is really just a fail-safe at this point as this client class should make sure
        # that the cookie is always set. However, when a custom http client is used, someone
        # might have cleared the cookies, so this is really just a safety net.
        if self.http_client.cookies.get("x-a3s-token", domain=domain) is None:
            ret["Authorization"] = "Bearer " + self.token

        # accept header depends on the use of msgpack
        if self._use_msgpack:
            ret["Accept"] = "application/msgpack"
        else:
            ret["Accept"] = "application/json"

        # if this is a POST or PUT, then the Content-Type again depends on the use of msgpack
        if method == "POST" or method == "PUT":
            if self._use_msgpack:
                ret["Content-Type"] = "application/msgpack"
            else:
                ret["Content-Type"] = "application/json; charset=utf-8"

        return ret

    def __retry_decorator(func):
        """
        Custom decorator to derive retry configuration from the instance itself.
        """
        @functools.wraps(func)
        def retry_wrapper(self, *args, **kwargs):
            # Retry mechanism is based on tenacity, which is a general-purpose retrying library
            #
            # chosen algorithm: we are using wait_random_exponential which is an exponential backoff algorithm with added jitter
            retry_decorator = retry(
                retry=retry_if_exception_type(RequestRetryException),
                wait=wait_random_exponential(multiplier=1, min=1, max=60),
                stop=(stop_after_delay(self._retry_max_wait) | stop_after_attempt(self._retry_max_attempts)),
            )
            decorated_func = retry_decorator(func)
            return decorated_func(self, *args, **kwargs)
        return retry_wrapper

    @__retry_decorator
    def _make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        # For retrying requests, we should retry on the same or similar conditions as the golang manipulate library:
        # - the same HTTP status codes as in the golang manipulate library:
        # - IO errors
        # - potential connection errors
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if domain == "":
            raise ValueError(f"_make_request: no domain in URL: {url}")
        headers = self._build_headers(method, domain)
        try:
            resp = self.http_client.request(
                method, url,
                headers=headers,
                **kwargs,
            )
            resp.raise_for_status()
        except httpx.CloseError as e:
            # nothing to fix here, also not harmful at all
            # do nothing
            logger.warning(f"Request to {url} encountered a CloseError: {e}. Ignoring this error.")
        except httpx.UnsupportedProtocol as e:
            # nothing to fix here, just raise
            # but as it is a TransportError, we need to catch it here
            raise e
        except httpx.ProtocolError as e:
            # nothing to fix here, just raise
            # but as it is a TransportError, we need to catch it here
            raise e
        except httpx.ConnectError as e:
            # unfortunately, we cannot distinguish between SSL errors and simple network connection problems
            # it would really be great if ssl.SSLError would be a cause somewhere in the chain
            # we resort to string matching
            err_str = str(e)
            if "SSL:" in err_str:
                # SSL errors cannot be retried, just raise
                raise e
            # otherwise we treat it like a TransportError and retry
            # this can be simple network connection problems which can be temporary
            logger.warning(f"Request to {url} failed with ConnectError: {e}. Retrying...")
            raise RequestRetryException(f"ConnectError: {e}")
        except httpx.TransportError as e:
            logger.warning(f"Request to {url} failed with TransportError: {e}. Retrying...")
            raise RequestRetryException(f"TransportError: {e}")
        except httpx.HTTPStatusError as e:
            # we want to retry on certain status codes like the manipulate golang library:
            # - http.StatusBadGateway
            # - http.StatusServiceUnavailable
            # - http.StatusGatewayTimeout
            # - http.StatusLocked
            # - http.StatusRequestTimeout
            # - http.StatusTooManyRequests
            if resp.status_code in [502, 503, 504, 423, 408, 429]:
                logger.warning(f"Request to {url} failed with HTTP status: {resp.status_code}. Retrying...")
                raise RequestRetryException(f"HTTPStatusError: {e}")
            else:
                # this itself can fail, so we are going to be conservative here and simply raise the exception if we cannot decode the error contents
                try:
                    elem_err = self._obj_from_content(ElementalError, resp.content, resp.headers.get('Content-Type'))
                    elem_err_json = ', '.join([e.model_dump_json() for e in elem_err]) if isinstance(elem_err, List) else elem_err.model_dump_json()
                except Exception:
                    if resp.status_code == 422:
                        logger.error(f"Request to {url} failed with HTTP status {resp.status_code}: {resp.text}. This means your 'acuvity' library is probably outdated and we are sending incompatible data. Please update to the latest version.")
                        raise OutdatedLibraryException(message=f"Request to {url} failed with HTTP status {resp.status_code}: {resp.text}. This means your 'acuvity' library is probably outdated and we are sending incompatible data. Please update to the latest version.") from e
                    logger.error(f"Request to {url} failed with HTTP status {resp.status_code}: {resp.text}")
                    raise e
                if resp.status_code == 422:
                    logger.error(f"Request to {url} failed with HTTP status {resp.status_code}: {elem_err_json}. This means your 'acuvity' library is probably outdated and we are sending incompatible data. Please update to the latest version.")
                    raise OutdatedLibraryException(message=f"Request to {url} failed with HTTP status {resp.status_code}: {elem_err_json}. This means your 'acuvity' library is probably outdated and we are sending incompatible data. Please update to the latest version.") from e
                logger.error(f"Request to {url} failed with HTTP status {resp.status_code}: {elem_err_json}")
                raise AcuvityClientException(elem_err, f"Request to {url} failed with HTTP status {resp.status_code}: {elem_err_json}") from e
        except Exception as e:
            logger.error(f"Request to {url} failed with unexpected error: {e}.")
            raise e

        return resp

    def _obj_from_content(self, object_class: Type[ElementalObject], content: bytes, content_type: Optional[str]) -> Union[ElementalObject, List[ElementalObject]]:
        data: Any = None
        if content_type is not None and isinstance(content_type, str) and content_type.lower().startswith("application/msgpack"):
            logger.debug("Content-Type is msgpack")
            data = msgpack.unpackb(content)       
        elif content_type is not None and isinstance(content_type, str) and content_type.lower().startswith("application/json"):
            logger.debug("Content-TYpe is JSON")
            data = json.loads(content)
        else:
            logger.warning(f"Unknown or unsupported Content-Type: {content_type}. Trying to use JSON decoder.")
            data = json.loads(content)

        try:
            if isinstance(data, list):
                return [object_class.model_validate(item) for item in data]
            else:
                return object_class.model_validate(data)
        except ValidationError as e:
            # This means that our types that we are receiving are probably out of date and incompatible with our pydantic types.
            # Give the user a hint that they need to update.
            logger.error(f"Failed to validate model: {e}. This means your 'acuvity' library is probably outdated and we are receiving data which is incompatible with our models. Please update to the latest version.")
            raise OutdatedLibraryException(message="Failed to validate model. This means your 'acuvity' library is probably outdated and we are receiving data which is incompatible with our models. Please update to the latest version.") from e

    def _obj_to_content(self, obj: Union[ElementalObject, List[ElementalObject]]) -> bytes:
        if isinstance(obj, list):
            data = [item.model_dump() for item in obj]
        else:
            data = obj.model_dump()
        return msgpack.packb(data) if self._use_msgpack else json.dumps(data).encode('utf-8')

    def apex_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        return self._make_request(method, self.apex_url + path, **kwargs)

    def apex_get(self, path: str, response_object_class: Type[ResponseElementalObject], **kwargs) -> Union[ResponseElementalObject, List[ResponseElementalObject]]:
        resp = self.apex_request("GET", path, **kwargs)
        return self._obj_from_content(response_object_class, resp.content, resp.headers.get('Content-Type'))
    
    def apex_post(self, path: str, obj: Union[RequestElementalObject, List[RequestElementalObject]], response_object_class: Type[ResponseElementalObject], **kwargs) -> Union[ResponseElementalObject, List[ResponseElementalObject]]:
        content = self._obj_to_content(obj)
        resp = self.apex_request("POST", path, content=content, **kwargs)
        return self._obj_from_content(response_object_class, resp.content, resp.headers.get('Content-Type'))

    def api_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        return self._make_request(method, self.api_url + path, **kwargs)

    def api_get(self, path: str, object_class: Type[ResponseElementalObject], **kwargs) -> Union[ResponseElementalObject, List[ResponseElementalObject]]:
        resp = self.api_request("GET", path, **kwargs)
        return self._obj_from_content(object_class, resp.content, resp.headers.get('Content-Type'))

    def api_post(self, path: str, obj: Union[RequestElementalObject, List[RequestElementalObject]], response_object_class: Type[ResponseElementalObject], **kwargs) -> Union[ResponseElementalObject, List[ResponseElementalObject]]:
        content = self._obj_to_content(obj)
        resp = self.api_request("POST", path, content=content, **kwargs)
        return self._obj_from_content(response_object_class, resp.content, resp.headers.get('Content-Type'))

    def well_known_apex_info(self) -> ApexInfo:
        # we know for a fact that the well known apex endpoint is going to perform a redirect
        # unfortunately for us, it is going to be very likely a redirect to a different domain from the API as well as the Apex
        # so we temporarily set this response event hook here while performing this request
        def event_handler(response: httpx.Response):
            if response.is_redirect:
                redirect_url = response.headers.get("Location")
                if redirect_url:
                    parsed_url = urlparse(redirect_url)
                    # use hostname as opposed to netloc because we *only* want the domain, and not the domain:port notation
                    domain = parsed_url.hostname
                    if domain != "":
                        self.http_client.cookies.set("x-a3s-token", self.token, domain=domain)

        original_hooks = self.http_client.event_hooks["response"]
        self.http_client.event_hooks["response"] = original_hooks + [event_handler]

        try:
            ret = self.api_get("/.well-known/acuvity/my-apex.json", ApexInfo, follow_redirects=True)
        except Exception as e:
            self.http_client.event_hooks["response"] = original_hooks
            raise e
        self.http_client.event_hooks["response"] = original_hooks

        return ret

# TODO: implement async client as well
#class AsyncAcuvityProxyClient:
#    def __init__(self):
#        pass
