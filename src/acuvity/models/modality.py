"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from acuvity.types import BaseModel
from typing_extensions import TypedDict


class ModalityTypedDict(TypedDict):
    r"""Represents the modality of a some data."""

    group: str
    r"""The group of data."""
    type: str
    r"""The type of data."""


class Modality(BaseModel):
    r"""Represents the modality of a some data."""

    group: str
    r"""The group of data."""

    type: str
    r"""The type of data."""
