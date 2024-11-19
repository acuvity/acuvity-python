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

import os
import httpx
import json
import jwt
import logging
import functools

from .apex_types import ElementalObject, RequestElementalObject, ResponseElementalObject, ElementalError, ExtractionRequest, ScanRequest, ScanResponse, ScanRequestAnonymizationEnum, ScanRequestTypeEnum, ScanExternalUser, Analyzer
from .api_types import ApexInfo
from pydantic import ValidationError

from typing import Any, Iterable, List, Type, Dict, Sequence, Union, Optional, Tuple
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


class AcuvityClient:
    """
    AcuvityClient is a synchronous client to use the Acuvity API or more importantly the Acuvity Apex API
    which is the center piece for the Python SDK.

    It offers the Acuvity Scan APIs in convenience wrappers around the actual API calls.
    """
    def __init__(
            self,
            *,
            token: Optional[str] = None,
            namespace: Optional[str] = None,
            api_url: Optional[str] = None,
            apex_url: Optional[str] = None,
            http_client: Optional[httpx.Client] = None,
            use_msgpack: bool = False,
            retry_max_attempts: int = 10,
            retry_max_wait: int = 300,
    ):
        """
        Initializes a new Acuvity client. At a minimum you need to provide a token, which can get passed through an environment variable.
        The rest of the values can be detected from and/or with the token.

        :param token: the API token to use for authentication. If not provided, it will be detected from the environment variable ACUVITY_TOKEN. If that fails, the initialization fails.
        :param namespace: the namespace to use for the API calls. If not provided, it will be detected from the environment variable ACUVITY_NAMESPACE or it will be derived from the token. If that fails, the initialization fails.
        :param api_url: the URL of the Acuvity API to use. If not provided, it will be detected from the environment variable ACUVITY_API_URL or it will be derived from the token. If that fails, the initialization fails.
        :param apex_url: the URL of the Acuvity Apex service to use. If not provided, it will be detected from the environment variable ACUVITY_APEX_URL or it will be derived from an API call. If that fails, the initialization fails.
        :param http_client: the HTTP client to use for making requests. If not provided, a new client will be created.
        :param use_msgpack: whether to use msgpack for serialization. If True, the 'msgpack' extra must be installed, and this will raise an exception otherwise. Defaults to False even if msgpack is installed. This must be be specifically enabled to get used.
        :param retry_max_attempts: the maximum number of retry attempts to make on failed requests that can be retried. Defaults to 10.
        :param retry_max_wait: the maximum number of seconds to wait for all retry attempts. Defaults to 300 seconds.
        """

        # take the values as is
        self._retry_max_attempts: int = retry_max_attempts
        self._retry_max_wait: int = retry_max_wait

        # we make sure we have an available property for the analyzers
        # however, we simply set this to None, and we'll initialize it later lazily when needed
        self._available_analyzers: Optional[List[Analyzer]] = None

        # check for msgpack
        if use_msgpack:
            if not HAVE_MSGPACK:
                raise ValueError("msgpack is not available, but use_msgpack is set to True. Install 'acuvity' with msgpack enabled: 'acuvity[msgpack]'")
            self._use_msgpack = True
        else:
            self._use_msgpack = False

        # we initialize the client early as we might require it to fully initialize our own client
        self.http_client = http_client if http_client is not None else httpx.Client(
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
        if apex_url is None or apex_url == "":
            try:
                apex_info = self.well_known_apex_info()
            except Exception as e:
                raise ValueError("failed to detect apex URL: could not retrieve well-known Apex info") from e
            apex_port = f":{apex_info.port}" if apex_info.port is not None else ""
            apex_url = f"https://{apex_info.url}{apex_port}" if not apex_info.url.startswith(("https://", "http://")) else f"{apex_info.url}{apex_port}"
        self.apex_url = apex_url

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

    def _build_headers(self, method: str, domain: Optional[str] = None) -> Dict[str, str]:
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
        domain = parsed_url.hostname
        if domain == "":
            raise ValueError(f"_make_request: no domain in URL: {url}")
        if domain != self.api_domain and domain != self.apex_domain:
            domain = None
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
            logger.debug("Content-Type is JSON")
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

    def scan(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        type: Union[ScanRequestTypeEnum,str] = ScanRequestTypeEnum.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        analyzers: Optional[List[str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[ScanRequestAnonymizationEnum, str, None] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
    ) -> ScanResponse:
        """
        scan() runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a ScanResponse object on success, and raises different exceptions on failure.

        This function allows to use and try different analyzers and make use of the redaction feature.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages or a direct request object are provided. Can be used in addition to messages.
        :param type: the type of the validation. This can be either ScanRequestTypeEnum.INPUT or ScanRequestTypeEnum.OUTPUT. Defaults to ScanRequestTypeEnum.INPUT. Use ScanRequestTypeEnum.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param analyzers: the analyzers to use. These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use "+" to include an analyzer and "-" to exclude an analyzer. For example, ["+image-classifier", "-modality-detector"] will include the image classifier and exclude the modality detector. If any analyzer does not start with a '+' or '-', then the default analyzers will be replaced by whatever is provided. Call `list_analyzers()` and/or its variants to get a list of available analyzers.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, but the returned detections contain redactions, then the system will use the internal defaults for anonymization which is subject to change.
        :param redactions: the redactions to apply. If your want to redact certain parts of the returned detections, you can provide a list of redactions that you want to apply. If not provided, no redactions will be applied.
        :param keywords: the keywords to detect in the input. If you want to detect certain keywords in the input, you can provide a list of keywords that you want to detect. If not provided, no keyword detection will be run.
        """
        return self.__scan(
            *messages,
            files=files,
            type=type,
            annotations=annotations,
            analyzers=analyzers,
            bypass_hash=bypass_hash,
            anonymization=anonymization,
            redactions=redactions,
            keywords=keywords,
        )

    def scan_and_police(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        type: Union[ScanRequestTypeEnum,str] = ScanRequestTypeEnum.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        user: Union[ScanExternalUser,Tuple[str, List[str]],Dict[str, Any]] = None,
        access_policy: Optional[str] = None,
        content_policy: Optional[str] = None,
    ) -> ScanResponse:
        """
        scan_and_police() runs the provided messages (prompts) through the Acuvity detection engines, applies policies, and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a ScanResponse object on success, and raises different exceptions on failure.

        You **must** provide a user to run this function.

        This function does **NOT** allow to use different analyzers or redactions as policies are being **managed** by the Acuvity backend.
        To configure different analyzers and redactions you must do so in the Acuvity backend.
        You can run *additional* access policies and content policies by passing them as parameters. However, these are additional policies and the main policies are being determined by the provided user, and will be applied and enforced first.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages or a direct request object are provided. Can be used in addition to messages.
        :param type: the type of the validation. This can be either ScanRequestTypeEnum.INPUT or ScanRequestTypeEnum.OUTPUT. Defaults to ScanRequestTypeEnum.INPUT. Use ScanRequestTypeEnum.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        """
        if user is None:
            raise ValueError("no user provided")
        if isinstance(user, tuple):
            if len(user) != 2:
                raise ValueError("user tuple must have exactly 2 elements to represent the name and claims")
            if not isinstance(user[0], str):
                raise ValueError("user tuple first element must be a string to represent the name")
            if not isinstance(user[1], list):
                raise ValueError("user tuple second element must be a list to represent the claims")
            for claim in user[1]:
                if not isinstance(claim, str):
                    raise ValueError("user tuple second element must be a list of strings to represent the claims")
            u = ScanExternalUser(name=user[0], claims=user[1])
        elif isinstance(user, dict):
            name = user.get("name", None)
            if name is None:
                raise ValueError("user dictionary must have a 'name' key to represent the name")
            if not isinstance(name, str):
                raise ValueError("user dictionary 'name' key must be a string to represent the name")
            claims = user.get("claims", None)
            if claims is None:
                raise ValueError("user dictionary must have a 'claims' key to represent the claims")
            if not isinstance(claims, list):
                raise ValueError("user dictionary 'claims' key must be a list to represent the claims")
            for claim in claims:
                if not isinstance(claim, str):
                    raise ValueError("user dictionary 'claims' key must be a list of strings to represent the claims")
            u = ScanExternalUser(name=name, claims=claims)
        elif isinstance(user, ScanExternalUser):
            u = user
        else:
            raise ValueError("user must be a tuple, dictionary or ScanExternalUser object")

        return self.__scan(
            *messages,
            files=files,
            type=type,
            annotations=annotations,
            user=u,
            access_policy=access_policy,
            content_policy=content_policy,
        )

    def scan_request(self, request: ScanRequest) -> ScanResponse:
        """
        scan_request() runs the provided ScanRequest object through the Acuvity detection engines and returns the results.
        This is the most advanced option to use the scan API and provides you with the most customization. However, it is not recommended to use this if you don't need anything that cannot be done without it.
        For most use cases, the scan() and scan_and_police() functions are sufficient.

        :param request: the raw request object to send to scan
        """

        return self.__scan(request=request)

    def __scan(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request: Optional[ScanRequest] = None,
        type: Union[ScanRequestTypeEnum,str] = ScanRequestTypeEnum.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        analyzers: Optional[List[str]] = None,
        bypass_hash: Optional[str] = None,
        anonymization: Union[ScanRequestAnonymizationEnum, str, None] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        user: Optional[ScanExternalUser] = None,
        access_policy: Optional[str] = None,
        content_policy: Optional[str] = None,
    ) -> ScanResponse:
        if request is None:
            request = ScanRequest.model_construct()

            # messages must be strings
            for message in messages:
                if not isinstance(message, str):
                    raise ValueError("messages must be strings")
            if len(messages) == 0 and files is None and request is None:
                raise ValueError("no messages, no files and no request object provided")
            if len(messages) > 0:
                request.messages = [message for message in messages]

            # files must be a list of strings (or paths) or a single string (or path)
            extractions: List[ExtractionRequest] = []
            if files is not None:
                process_files = []
                if isinstance(files, str):
                    process_files.append(files)
                elif isinstance(files, os.PathLike):
                    process_files.append(files)
                elif isinstance(files, Iterable):
                    for file in files:
                        if not isinstance(file, str) and not isinstance(file, os.PathLike):
                            raise ValueError("files must be strings or paths")
                        process_files.append(file)
                else:
                    raise ValueError("files must be strings or paths")
                for process_file in process_files:
                    with open(process_file, 'rb') as file:
                        file_content = file.read()
                        extractions.append(ExtractionRequest(data=file_content))
            if len(extractions) > 0:
                request.extractions = extractions

            # type must be either "Input" or "Output"
            if isinstance(type, ScanRequestTypeEnum):
                request.type = type
            elif isinstance(type, str):
                if type != "Input" and type != "Output":
                    raise ValueError("type must be either 'Input' or 'Output'")
                request.type = ScanRequestTypeEnum(type)
            else:
                raise ValueError("type must be a 'str' or 'ScanRequestTypeEnum'")

            # annotations must be a dictionary of strings
            if annotations is not None:
                if not isinstance(annotations, dict):
                    raise ValueError("annotations must be a dictionary")
                for key, value in annotations.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        raise ValueError("annotations must be strings")
                request.annotations = annotations

            # analyzers must be a list of strings
            if analyzers is not None:
                if not isinstance(analyzers, List):
                    raise ValueError("analyzers must be a list")
                analyzers_list = self.list_analyzer_groups() + self.list_analyzer_names()
                for analyzer in analyzers:
                    if not isinstance(analyzer, str):
                        raise ValueError("analyzers must be strings")
                    if analyzer.startswith(("+", "-")):
                        analyzer = analyzer[1:]
                    if analyzer not in analyzers_list:
                        raise ValueError(f"analyzer '{analyzer}' is not in list of analyzer groups or analyzers: {analyzers_list}")
                request.analyzers = analyzers

            # bypass_hash must be a string
            if bypass_hash is not None:
                if not isinstance(bypass_hash, str):
                    raise ValueError("bypass_hash must be a string")
                request.bypass_hash = bypass_hash

            # anonymization must be "FixedSize" or "VariableSize"
            if anonymization is not None:
                if isinstance(anonymization, ScanRequestAnonymizationEnum):
                    request.anonymization = anonymization
                elif isinstance(anonymization, str):
                    if anonymization != "FixedSize" and anonymization != "VariableSize":
                        raise ValueError("anonymization must be 'FixedSize' or 'VariableSize'")
                    request.anonymization = ScanRequestAnonymizationEnum(anonymization)
                else:
                    raise ValueError("anonymization must be a 'str' or 'ScanRequestAnonymizationEnum'")

            # redactions must be a list of strings
            if redactions is not None:
                if not isinstance(redactions, List):
                    raise ValueError("redactions must be a list")
                for redaction in redactions:
                    if not isinstance(redaction, str):
                        raise ValueError("redactions must be strings")
                request.redactions = redactions

            # keywords must be a list of strings
            if keywords is not None:
                if not isinstance(keywords, List):
                    raise ValueError("keywords must be a list")
                for keyword in keywords:
                    if not isinstance(keyword, str):
                        raise ValueError("keywords must be strings")
                request.keywords = keywords

            # local access policy
            if access_policy is not None:
                if not isinstance(access_policy, str):
                    raise ValueError("access_policy must be a string")
                request.access_policy = access_policy

            # local content policy
            if content_policy is not None:
                if not isinstance(content_policy, str):
                    raise ValueError("content_policy must be a string")
                request.content_policy = content_policy

            # external user
            if user is not None:
                if not isinstance(user, ScanExternalUser):
                    raise ValueError("user must be a ScanExternalUser object")
                request.user = user

            # last but not least, ensure the request is valid now
            # if we were building this request, then this is a bug if it is not
            # and we should abort immediately
            try:
                ScanRequest.model_validate(request)
            except ValidationError as e:
                raise RuntimeError(f"BUG: request object is invalid: {e}") from e
        else:
            if not isinstance(request, ScanRequest):
                raise ValueError("request must be a ScanRequest object")
            try:
                ScanRequest.model_validate(request)
            except ValidationError as e:
                raise ValueError(f"request object is invalid: {e}") from e

        # now execute the request
        path = "/_acuvity/scan"
        return self.apex_post(path, request, ScanResponse)

    def list_analyzers(self) -> List[Analyzer]:
        """
        list_analyzers() returns a detailed list with descriptions of all available analyzers.

        If you are simply looking for a list of strings of available analyzers that you can pass to a scan request,
        you can use list_analyzer_names() and list_analyzer_groups() instead.
        """
        if self._available_analyzers is None:
            self._available_analyzers = self.apex_get("/_acuvity/analyzers", Analyzer)
        return self._available_analyzers

    def list_analyzer_groups(self) -> List[str]:
        """
        list_analyzer_groups() returns a list of all available analyzer groups. These can be passed in a scan request
        to activate/deactivate a whole group of analyzers at once.
        """
        if self._available_analyzers is None:
            self._available_analyzers = self.apex_get("/_acuvity/analyzers", Analyzer)
        return sorted(set([ a.group for a in self._available_analyzers ]))

    def list_analyzer_names(self, group: Optional[str] = None) -> List[str]:
        """
        list_analyzer_names() returns a list of all available analyzer names. These can be passed in a scan request
        to activate/deactivate specific analyzers.

        :param group: the group of analyzers to filter the list by. If not provided, all analyzers will be returned.
        """
        if self._available_analyzers is None:
            self._available_analyzers = self.apex_get("/_acuvity/analyzers", Analyzer)
        return sorted([ a.id for a in self._available_analyzers if group is None or a.group == group ])

# TODO: implement async client as well
#class AsyncAcuvityClient:
#    def __init__(self):
#        pass
