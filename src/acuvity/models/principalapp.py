"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from acuvity.types import BaseModel
from typing import List, Optional
from typing_extensions import NotRequired, TypedDict


class PrincipalappTypedDict(TypedDict):
    r"""Describes the principal information of an application."""

    labels: NotRequired[List[str]]
    r"""The list of labels attached to an application request."""
    name: NotRequired[str]
    r"""The name of the application."""
    tier: NotRequired[str]
    r"""The tier of the application request."""


class Principalapp(BaseModel):
    r"""Describes the principal information of an application."""

    labels: Optional[List[str]] = None
    r"""The list of labels attached to an application request."""

    name: Optional[str] = None
    r"""The name of the application."""

    tier: Optional[str] = None
    r"""The tier of the application request."""
