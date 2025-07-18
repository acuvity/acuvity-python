"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from acuvity.types import BaseModel
import pydantic
from typing import Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class ToolresultTypedDict(TypedDict):
    r"""Represents the tool result as passed in by the user or application after calling
    a tool.
    """

    call_id: str
    r"""The ID of the tool use as previously returned by a models tool use response."""
    content: NotRequired[str]
    r"""The content of the tool call results."""
    is_error: NotRequired[bool]
    r"""Indicates if the tool call failed."""


class Toolresult(BaseModel):
    r"""Represents the tool result as passed in by the user or application after calling
    a tool.
    """

    call_id: Annotated[str, pydantic.Field(alias="callID")]
    r"""The ID of the tool use as previously returned by a models tool use response."""

    content: Optional[str] = None
    r"""The content of the tool call results."""

    is_error: Annotated[Optional[bool], pydantic.Field(alias="isError")] = False
    r"""Indicates if the tool call failed."""
