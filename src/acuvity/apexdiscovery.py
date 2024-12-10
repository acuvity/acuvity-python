import jwt
from urllib.parse import urlparse
from typing import Callable, Optional, Union, Tuple, Any
from .httpclient import HttpClient
from acuvity import models
from acuvity.utils import get_security_from_env
from pydantic import BaseModel

def discover_apex(
    client: HttpClient,
    server_url: Optional[str] = None,
    security: Optional[
        Union[models.Security, Callable[[], models.Security]]
    ] = None,
    apex_domain: Optional[str] = None,
    apex_port: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    # pylint: disable=too-many-return-statements
    """
    Discovers the apex domain and port from the token by calling the backend API if the server_url is not provided.
    """
    # if a server_url was given, then we don't need to perform discovery at all
    if server_url is not None:
        return apex_domain, apex_port

    # if an apex_domain was given, then we also don't need to perform discovery
    if apex_domain is not None:
        return apex_domain, apex_port

    # if there is no token, then we can't perform discovery, and yes everything else will fail too
    token: str = ""
    sec: Optional[BaseModel] = get_security_from_env(security, models.Security)
    if sec is None or not isinstance(sec, models.Security):
        return apex_domain, apex_port
    token = sec.token if sec.token is not None else sec.cookie if sec.cookie is not None else ""
    if token == "":
        return apex_domain, apex_port

    # decode the token but don't verify the signature
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        if "iss" not in decoded_token:
            raise ValueError("token has no 'iss' field")
    except Exception:
        return apex_domain, apex_port

    # extract the API URL from the token
    api_url = decoded_token["iss"]
    if api_url == "":
        return apex_domain, apex_port

    def well_known_apex_info(client: HttpClient, token: str, url: str, iteration: int = 0) -> Any:
        if iteration == 3:
            return None
        req = client.build_request("GET", url, headers={"Authorization": f"Bearer {token}"})
        resp = client.send(req, follow_redirects=False) # following redirects automatically will remove the token from the call as headers are not going to be sent anymore
        if resp.is_redirect:
            return well_known_apex_info(client, token, resp.headers["Location"], iteration + 1)
        return resp.json()
    try:
        apex_info = well_known_apex_info(client, token, f"{api_url}/.well-known/acuvity/my-apex.json")
    except Exception:
        return apex_domain, apex_port

    try:
        # extract the information from the response
        apex_url = apex_info["url"]
        port = f"{apex_info['port']}"
        # parse the URL to extract the domain
        # use hostname as opposed to netloc because we *only* want the domain, and not the domain:port notation
        parsed_url = urlparse(apex_url)
        domain = parsed_url.hostname
        if port == "":
            raise ValueError("Apex Info: no port in response")
        if domain == "":
            raise ValueError(f"Apex Info: no domain in URL: f{apex_url}")
    except Exception:
        return apex_domain, apex_port

    return domain, port