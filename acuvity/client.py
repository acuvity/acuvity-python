import base64
import os
import httpx
import jwt

from typing import Iterable, List, Any, Dict, Sequence, Union, Optional
from urllib.parse import urlparse

class AcuvityClient:
    def __init__(
            self,
            *,
            token: Optional[str] = None,
            namespace: Optional[str] = None,
            api_url: Optional[str] = None,
            apex_url: Optional[str] = None,
            http_client: Optional[httpx.Client] = None,
    ):
        """
        Initializes a new Acuvity client. At a minimum you need to provide a token, which can get passed through an environment variable.
        The rest of the values can be detected from and/or with the token.

        :param token: the API token to use for authentication. If not provided, it will be detected from the environment variable ACUVITY_TOKEN. If that fails, the initialization fails.
        :param namespace: the namespace to use for the API calls. If not provided, it will be detected from the environment variable ACUVITY_NAMESPACE or it will be derived from the token. If that fails, the initialization fails.
        :param api_url: the URL of the Acuvity API to use. If not provided, it will be detected from the environment variable ACUVITY_API_URL or it will be derived from the token. If that fails, the initialization fails.
        :param apex_url: the URL of the Acuvity Apex service to use. If not provided, it will be detected from the environment variable ACUVITY_APEX_URL or it will be derived from an API call. If that fails, the initialization fails.
        :param http_client: the HTTP client to use for making requests. If not provided, a new client will be created.
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

        # we initialize the client early as we might require it to fully initialize our own client
        self.http_client = http_client if http_client is not None else httpx.Client(
            timeout=httpx.Timeout(timeout=600.0, connect=5.0),
            limits=httpx.Limits(max_connections=1000, max_keepalive_connections=100),
            follow_redirects=True,
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
                orgsettings = self.orgsettings()
                org_id = orgsettings["ID"]
            except Exception as e:
                raise ValueError("failed to detect apex URL: could not retrieve orgsettings: " + str(e))
            apex_url = f"https://{org_id}.{self.api_tld_domain}"
        self.apex_url = apex_url

        try:
            parsed_url = urlparse(apex_url)
            if parsed_url.netloc == "":
                raise ValueError("no domain in URL")
            if parsed_url.scheme != "https" and parsed_url.scheme != "http":
                raise ValueError(f"invalid scheme: {parsed_url.scheme}")
        except Exception as e:
            raise ValueError("Apex URL is not a valid URL: " + str(e))

    def orgsettings(self):
        """
        Retrieves the organization settings that the authenticated token belongs to.
        """
        resp_json = self.http_client.get(
            self.api_url + "/orgsettings",
            headers={
                "Authorization": "Bearer " + self.token,
                "X-Namespace": self.namespace,
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        if  resp_json.status_code != 200:
            raise ValueError(f"failed to call orgsettings API: HTTP {resp_json.status_code}: {resp_json.text}")
        resp = resp_json.json()

        # we know this is a singleton, so there will always be exactly one
        return resp[0]

    def validate(
            self,
            *messages: str,
            files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
            type: str = "Input",
            analyzers: Optional[List[str]] = None,
            annotations: Optional[Dict[str, str]] = None,
            bypass_hash: Optional[str] = None,
            anonymization: Optional[str] = None,
    ) -> Any:
        """
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

        resp_json = self.http_client.post(
            self.apex_url + "/_acuvity/validate",
            headers={
                "Authorization": "Bearer " + self.token,
                "X-Namespace": self.namespace,
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            },
            json=data,
        )
        if  resp_json.status_code != 200:
            raise ValueError(f"failed to call validate API: HTTP {resp_json.status_code}: {resp_json.text}")

        resp = resp_json.json()
        return resp

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
