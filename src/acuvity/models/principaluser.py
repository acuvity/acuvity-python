"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from acuvity.types import BaseModel
from typing import Optional
from typing_extensions import NotRequired, TypedDict


class PrincipaluserTypedDict(TypedDict):
    r"""Describes the principal information of a user."""

    name: NotRequired[str]
    r"""Identification bit that will be used to identify the origin of the request."""


class Principaluser(BaseModel):
    r"""Describes the principal information of a user."""

    name: Optional[str] = None
    r"""Identification bit that will be used to identify the origin of the request."""