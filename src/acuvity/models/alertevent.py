"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .principal import Principal, PrincipalTypedDict
from acuvity.types import BaseModel
from datetime import datetime
import pydantic
from typing import Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class AlerteventTypedDict(TypedDict):
    r"""Represents an alert event raised by a policy."""

    alert_definition: str
    r"""The name of the alert definition that triggered the alert event."""
    principal: PrincipalTypedDict
    r"""Describe the principal."""
    alert_definition_namespace: NotRequired[str]
    r"""The namespace of the alert definition."""
    provider: NotRequired[str]
    r"""The provider used that the alert came from."""
    timestamp: NotRequired[datetime]
    r"""When the alert event was raised."""


class Alertevent(BaseModel):
    r"""Represents an alert event raised by a policy."""

    alert_definition: Annotated[str, pydantic.Field(alias="alertDefinition")]
    r"""The name of the alert definition that triggered the alert event."""

    principal: Principal
    r"""Describe the principal."""

    alert_definition_namespace: Annotated[
        Optional[str], pydantic.Field(alias="alertDefinitionNamespace")
    ] = None
    r"""The namespace of the alert definition."""

    provider: Optional[str] = None
    r"""The provider used that the alert came from."""

    timestamp: Optional[datetime] = None
    r"""When the alert event was raised."""
