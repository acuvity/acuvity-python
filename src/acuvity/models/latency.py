"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from acuvity.types import BaseModel
import pydantic
from typing import Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class LatencyTypedDict(TypedDict):
    r"""Holds information about latencies introduced by Apex."""

    access_policy: NotRequired[int]
    r"""How much time it took to run the access policy in nanoseconds."""
    analysis: NotRequired[int]
    r"""How much time it took to run content analysis in nanoseconds."""
    assign_policy: NotRequired[int]
    r"""How much time it took to run the assign policy in nanoseconds."""
    content_policy: NotRequired[int]
    r"""How much time it took to run content policy in nanoseconds."""
    extraction: NotRequired[int]
    r"""How much time it took to run input or output extraction in nanoseconds."""


class Latency(BaseModel):
    r"""Holds information about latencies introduced by Apex."""

    access_policy: Annotated[Optional[int], pydantic.Field(alias="accessPolicy")] = None
    r"""How much time it took to run the access policy in nanoseconds."""

    analysis: Optional[int] = None
    r"""How much time it took to run content analysis in nanoseconds."""

    assign_policy: Annotated[Optional[int], pydantic.Field(alias="assignPolicy")] = None
    r"""How much time it took to run the assign policy in nanoseconds."""

    content_policy: Annotated[Optional[int], pydantic.Field(alias="contentPolicy")] = (
        None
    )
    r"""How much time it took to run content policy in nanoseconds."""

    extraction: Optional[int] = None
    r"""How much time it took to run input or output extraction in nanoseconds."""
