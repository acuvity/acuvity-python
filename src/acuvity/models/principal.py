"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .principalapp import Principalapp, PrincipalappTypedDict
from .principaluser import Principaluser, PrincipaluserTypedDict
from acuvity.types import BaseModel
from enum import Enum
import pydantic
from typing import List, Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class AuthType(str, Enum):
    r"""The type of authentication."""

    CERTIFICATE = "Certificate"
    USER_TOKEN = "UserToken"
    APP_TOKEN = "AppToken"
    HOSTNAME = "Hostname"
    TOKEN = "Token"
    TIER_TOKEN = "TierToken"
    EXTERNAL = "External"


class PrincipalType(str, Enum):
    r"""The type of principal."""

    USER = "User"
    APP = "App"


class PrincipalTypedDict(TypedDict):
    r"""Describe the principal."""

    type: PrincipalType
    r"""The type of principal."""
    app: NotRequired[PrincipalappTypedDict]
    r"""Describes the principal information of an application."""
    auth_type: NotRequired[AuthType]
    r"""The type of authentication."""
    claims: NotRequired[List[str]]
    r"""List of claims extracted from the user query."""
    team: NotRequired[str]
    r"""The team that was used to authorize the request."""
    token_name: NotRequired[str]
    r"""The name of the token, if any."""
    user: NotRequired[PrincipaluserTypedDict]
    r"""Describes the principal information of a user."""


class Principal(BaseModel):
    r"""Describe the principal."""

    type: PrincipalType
    r"""The type of principal."""

    app: Optional[Principalapp] = None
    r"""Describes the principal information of an application."""

    auth_type: Annotated[Optional[AuthType], pydantic.Field(alias="authType")] = None
    r"""The type of authentication."""

    claims: Optional[List[str]] = None
    r"""List of claims extracted from the user query."""

    team: Optional[str] = None
    r"""The team that was used to authorize the request."""

    token_name: Annotated[Optional[str], pydantic.Field(alias="tokenName")] = None
    r"""The name of the token, if any."""

    user: Optional[Principaluser] = None
    r"""Describes the principal information of a user."""
