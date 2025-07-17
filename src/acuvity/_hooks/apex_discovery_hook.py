"""Apex Discovery Hook for automatic apex domain and port discovery."""

from typing import Union, Optional
import httpx

from acuvity.apexdiscovery import discover_apex

from .types import BeforeRequestHook, BeforeRequestContext


class ApexDiscoveryHook(BeforeRequestHook):
    """Hook that automatically discovers apex domain and port during SDK initialization.

    This hook integrates with the SDK initialization process to automatically discover
    the apex domain and port based on the security token, eliminating the need for
    manual configuration in most cases.
    """

    cached_apex_domain: Optional[str] = None
    cached_apex_port: Optional[int] = None

    @staticmethod
    def update_request_domain(request: httpx.Request, host: str, port: int) -> None:
        """Updates the url of a request to the specified domain and port."""
        new_url = request.url.copy_with(host=host, port=port)
        request.url = new_url

    def before_request(
        self, hook_ctx: BeforeRequestContext, request: httpx.Request
    ) -> Union[httpx.Request, Exception]:
        if self.cached_apex_domain is not None and self.cached_apex_port is not None:
            ApexDiscoveryHook.update_request_domain(
                request,
                self.cached_apex_domain,
                self.cached_apex_port,
            )
            return request

        server_details = hook_ctx.config.get_server_details()[1]
        apex_domain = server_details.get("apex_domain")
        apex_port = server_details.get("apex_port")

        # If these aren't present, then this hook can't function and should raise an error
        if not apex_domain or not apex_port:
            hook_ctx.config.debug_logger.debug(
                f"A problem occured in '{self.__class__.__name__} - '"
                + "apex_domain and apex_port were not passed, but should have at least received defaults. "
                + "The OpenAPI specification may have removed these params, or SDK initialization "
                + "has changed to become incompatible with this hook."
            )
            raise ValueError(
                "Apex domain and port must be set in the server details for apex discovery."
            )

        # If the client is not set, then this hook can't function and should raise an error
        if not hook_ctx.config.client:
            hook_ctx.config.debug_logger.debug(
                f"A problem occured in '{self.__class__.__name__}' - the HttpClient was not available. "
                + "The SDK initialization logic may have changed to become incompatible with this hook."
            )
            raise ValueError(
                "Client must be set in the SDK configuration for apex discovery."
            )

        discovered_domain, discovered_port = discover_apex(
            client=hook_ctx.config.client,
            server_url=hook_ctx.config.server_url,
            security=hook_ctx.security_source,
            apex_domain=None,
            apex_port=None,
        )

        if not discovered_domain or not discovered_port:
            return request

        # cache values so we don't have to do this again
        self.cached_apex_domain = discovered_domain
        self.cached_apex_port = int(discovered_port)

        ApexDiscoveryHook.update_request_domain(
            request, self.cached_apex_domain, self.cached_apex_port
        )

        return request

