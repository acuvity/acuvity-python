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

import base64
import os
import ssl
import httpx
import json
import jwt

from .types import AO, ApexInfo, ValidateRequest, ValidateResponse

from typing import Iterable, List, Type, Dict, Sequence, Union, Optional
from urllib.parse import urlparse

# msgpack is optional and sits behind a 'msgpack' extra
try:
    import msgpack
    HAVE_MSGPACK = True
except ImportError:
    HAVE_MSGPACK = False

class AcuvityClient:
    def __init__(
            self,
            *,
            token: Optional[str] = None,
            namespace: Optional[str] = None,
            api_url: Optional[str] = None,
            apex_url: Optional[str] = None,
            use_msgpack: bool = HAVE_MSGPACK,
    ):
        """
        Initializes a new Acuvity client. At a minimum you need to provide a token, which can get passed through an environment variable.
        The rest of the values can be detected from and/or with the token.

        :param token: the API token to use for authentication. If not provided, it will be detected from the environment variable ACUVITY_TOKEN. If that fails, the initialization fails.
        :param namespace: the namespace to use for the API calls. If not provided, it will be detected from the environment variable ACUVITY_NAMESPACE or it will be derived from the token. If that fails, the initialization fails.
        :param api_url: the URL of the Acuvity API to use. If not provided, it will be detected from the environment variable ACUVITY_API_URL or it will be derived from the token. If that fails, the initialization fails.
        :param apex_url: the URL of the Acuvity Apex service to use. If not provided, it will be detected from the environment variable ACUVITY_APEX_URL or it will be derived from an API call. If that fails, the initialization fails.
        :param use_msgpack: whether to use msgpack for serialization. If True, the 'msgpack' extra must be installed, and this will raise an exception otherwise. Defaults to True if msgpack is installed.
        """

        # we initialize the available analyzers here as they are static right now
        # this will need to change once they become dynamic, but even then we can cache them within the client
        self._available_analyzers = {
            "PIIs": [
                "ner_detector",
                "pii_detector",
            ],
            "Secrets": [
                "secrets_detector",
            ],
            "Topics": [
                "text_multi_classifier",
                "text_classifier_corporate",
            ],
            "Exploits": [
                "prompt_injection",
                "harmful_content",
                "jailbreak",
            ],
            "Languages": [
                "language_detector",
                "gibberish_detector",
            ],
        }

        # check for msgpack
        if use_msgpack:
            if not HAVE_MSGPACK:
                raise ValueError("msgpack is not available, but use_msgpack is set to True")
            self._use_msgpack = True
        else:
            self._use_msgpack = False

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
            domain = parsed_url.netloc
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
            namespace = decoded_token["source"]["namespace"]
        if namespace is None or namespace == "":
            raise ValueError("no namespace provided or detected")
        self.namespace = namespace

        # and last but not least, the apex URL which is the service/proxy that provides the APIs
        # that we want to actually use in this client
        if apex_url is None:
            apex_url = os.getenv("ACUVITY_APEX_URL", None)
        if apex_url is None or apex_url == "":
            try:
                apex_info = self.well_known_apex_info()
                if apex_info.cas is not None and apex_info.cas != "":
                    # if the API provided us with Apex CA certs, we're going to recreate the
                    # http_client to make use of them.
                    sslctx = ssl.create_default_context()
                    sslctx.load_verify_locations(cadata=apex_info.cas)
                    self.http_client = httpx.Client(
                        timeout=httpx.Timeout(timeout=600.0, connect=5.0),
                        limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
                        follow_redirects=True,
                        http2=True,
                        verify=sslctx,
                    )
            except Exception as e:
                raise ValueError("failed to detect apex URL: could not retrieve well-known Apex info: " + str(e))
            apex_url = f"https://{apex_info.url}" if not apex_info.url.startswith(("https://", "http://")) else apex_info.url
        self.apex_url = apex_url

        try:
            parsed_url = urlparse(apex_url)
            if parsed_url.netloc == "":
                raise ValueError("no domain in URL")
            if parsed_url.scheme != "https" and parsed_url.scheme != "http":
                raise ValueError(f"invalid scheme: {parsed_url.scheme}")
        except Exception as e:
            raise ValueError("Apex URL is not a valid URL: " + str(e))

    def _build_headers(self, method: str) -> Dict[str, str]:
        # we always send our token and namesp
        ret = {
            "Authorization": "Bearer " + self.token,
            "X-Namespace": self.namespace,
        }

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
                ret["Content-Type"] = "application/json; charset=utf-8",

        return ret

    def _make_request(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = self._build_headers(method)
        resp = self.http_client.request(
            method, url,
            headers=headers,
            **kwargs,
        )
        return resp

    def _obj_from_content(self, object_class: Type[AO], content: bytes) -> Union[AO, List[AO]]:
        data = msgpack.unpackb(content) if self._use_msgpack else json.loads(content)
        if isinstance(data, list):
            return [object_class.model_validate(item) for item in data]
        else:
            return object_class.model_validate(data)

    def _obj_to_content(self, obj: Union[AO, List[AO]]) -> bytes:
        if isinstance(obj, list):
            data = [item.model_dump() for item in obj]
        else:
            data = obj.model_dump()
        return msgpack.packb(data) if self._use_msgpack else json.dumps(data).encode('utf-8')

    def apex_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        return self._make_request(method, self.apex_url + path, **kwargs)

    def apex_get(self, path: str, object_class: Type[AO], **kwargs) -> Union[AO, List[AO]]:
        resp = self.apex_request("GET", path, **kwargs)
        return self._obj_from_content(object_class, resp.content)
    
    def apex_post(self, path: str, obj: Union[AO, List[AO]], **kwargs) -> None:
        content = self._obj_to_content(obj)
        self.apex_request("POST", path, content=content, **kwargs)
        return None

    def api_request(self, method: str, path: str, **kwargs) -> httpx.Response:
        return self._make_request(method, self.api_url + path, **kwargs)

    def api_get(self, path: str, object_class: Type[AO], **kwargs) -> Union[AO, List[AO]]:
        resp = self.api_request("GET", path, **kwargs)
        return self._obj_from_content(object_class, resp.content)

    def api_post(self, path: str, obj: Union[AO, List[AO]], **kwargs) -> None:
        content = self._obj_to_content(obj)
        self.api_request("POST", path, content=content, **kwargs)
        return None

    def well_known_apex_info(self) -> ApexInfo:
        return self.api_get("/.well-known/acuvity/my-apex.json", ApexInfo)

    def validate(
            self,
            *messages: str,
            files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
            type: str = "Input",
            analyzers: Optional[List[str]] = None,
            annotations: Optional[Dict[str, str]] = None,
            bypass_hash: Optional[str] = None,
            anonymization: Optional[str] = None,
            redactions: Optional[List[str]] = None,
            keywords: Optional[List[str]] = None,
    ) -> ValidateResponse:
        """
        Validate runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a ValidateResponse object on success, and raises different exceptions on failure.

        :param messages: the messages to validate. These are the prompts that you want to validate. Required if no files are provided.
        :param files: the files to validate. These are the files that you want to validate. Required if no messages are provided.
        :param type: the type of the validation. This can be either "Input" or "Output". Defaults to "Input". Use "Output" if you want to run model output through the detection engines.
        :param analyzers: the analyzers to use. These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use "+" to include an analyzer and "-" to exclude an analyzer. For example, ["+pii_detector", "-ner_detector"] will include the PII detector and exclude the NER detector.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param bypass_hash: the bypass hash to use. This is the hash that you want to use to bypass the detection engines. If not provided, no bypass hash will be used.
        :param anonymization: the anonymization to use. This is the anonymization that you want to use. If not provided, no anonymization will be used.
        """
        data = {}
        # messages must be strings
        for message in messages:
            if not isinstance(message, str):
                raise ValueError("messages must be strings")
        if len(messages) == 0 and files is None:
            raise ValueError("no messages and no files provided")
        if len(messages) > 0:
            data["messages"] = [message for message in messages]

        # files must be a list of strings (or paths) or a single string (or path)
        extractions = []
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
                    encoded_content = base64.b64encode(file_content).decode('utf-8')
                    extractions.append({
                        "content": encoded_content,
                    })
        if len(extractions) > 0:
            data["extractions"] = extractions

        # type must be either "Input" or "Output"
        if type != "Input" and type != "Output":
            raise ValueError("type must be either 'Input' or 'Output'")
        data["type"] = type

        # analyzers must be a list of strings
        if analyzers is not None:
            if not isinstance(analyzers, List):
                raise ValueError("analyzers must be a list")
            for analyzer in analyzers:
                if not isinstance(analyzer, str):
                    raise ValueError("analyzers must be strings")
                if not analyzer.startswith(("+", "-")):
                    raise ValueError("analyzers does not start with '+' or '-' to indicate inclusion or exclusion: " + analyzer)
            data["analyzers"] = analyzers

        # annotations must be a dictionary of strings
        if annotations is not None:
            if not isinstance(annotations, dict):
                raise ValueError("annotations must be a dictionary")
            for key, value in annotations.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError("annotations must be strings")
            data["annotations"] = annotations

        # bypass_hash must be a string
        if bypass_hash is not None:
            if not isinstance(bypass_hash, str):
                raise ValueError("bypass_hash must be a string")
            data["bypass"] = bypass_hash

        # anonymization must be "FixedSize" or "VariableSize"
        if anonymization is not None:
            if anonymization != "FixedSize" and anonymization != "VariableSize":
                raise ValueError("anonymization must be 'FixedSize' or 'VariableSize'")
            data["anonymization"] = anonymization

        # redactions must be a list of strings
        if redactions is not None:
            if not isinstance(redactions, List):
                raise ValueError("redactions must be a list")
            for redaction in redactions:
                if not isinstance(redaction, str):
                    raise ValueError("redactions must be strings")
            data["redactions"] = redactions

        # keywords must be a list of strings
        if keywords is not None:
            if not isinstance(keywords, List):
                raise ValueError("keywords must be a list")
            for keyword in keywords:
                if not isinstance(keyword, str):
                    raise ValueError("keywords must be strings")
            data["keywords"] = keywords

        resp = self.http_client.post(
            self.apex_url + "/_acuvity/validate/unmanaged",
            headers={
                "Authorization": "Bearer " + self.token,
                "X-Namespace": self.namespace,
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=data,
        )
        if resp.status_code != 200:
            raise ValueError(f"failed to call validate API: HTTP {resp.status_code}: {resp.text}")

        # TODO: account for msgpack
        # ret = resp.json()
        ret = ValidateResponse.model_validate_json(resp.content)
        return ret

    def list_analyzer_groups(self) -> List[str]:
        return list(self._available_analyzers.keys())
    
    def list_analyzers(self, group: str | None = None) -> List[str]:
        if group is None:
            return [analyzer for analyzers in self._available_analyzers.values() for analyzer in analyzers]
        return self._available_analyzers[group]


# TODO: implement async client as well
#class AsyncAcuvityClient:
#    def __init__(self):
#        pass
