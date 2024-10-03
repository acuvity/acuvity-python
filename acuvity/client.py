import httpx
import jwt
import os

from urllib.parse import urlparse

class AcuvityClient:
    def __init__(
            self,
            *,
            token: str | None = None,
            namespace: str | None = None,
            api_url: str | None = None,
            apex_url: str | None = None,
            http_client: httpx.Client | None = None,
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

        # we initialize the client early as we might require it to fully initialize our own client
        self.http_client = http_client if http_client is not None else httpx.Client()

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
        resp = self.http_client.get(
            self.api_url + "/orgsettings",
            headers={
                "Authorization": "Bearer " + self.token,
                "X-Namespace": self.namespace,
                "Accept": "application/json",
                "Content-Type": "application/json; charset=utf-8",
            },
        )
        resp_json = resp.json()
        return resp_json[0]

# TODO: implement async client as well
#class AsyncAcuvityClient:
#    def __init__(self):
#        pass
