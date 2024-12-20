"""Code generated by Speakeasy (https://speakeasy.com). DO NOT EDIT."""

from __future__ import annotations
from .extractionrequest import Extractionrequest, ExtractionrequestTypedDict
from acuvity.types import BaseModel
from enum import Enum
import pydantic
from typing import Dict, List, Optional
from typing_extensions import Annotated, NotRequired, TypedDict


class ScanrequestAnonymization(str, Enum):
    r"""How to anonymize the data. If deanonymize is true, then VariablSize is required."""

    FIXED_SIZE = "FixedSize"
    VARIABLE_SIZE = "VariableSize"


class ScanrequestType(str, Enum):
    r"""The type of text."""

    INPUT = "Input"
    OUTPUT = "Output"


class ScanrequestTypedDict(TypedDict):
    r"""This is a scan request."""

    access_policy: NotRequired[str]
    r"""AccessPolicy allows to pass optional Rego access policy. If not set,
    The action is always Allow,
    If it is set, it will be run, and the final decision will be computed based
    on that policy.
    If the rego code does not start with package main, then the needed
    classic package definition and  acuvity imports will be added
    automatically.
    If the code starts with package main, then everything remains untouched.
    """
    analyzers: NotRequired[List[str]]
    r"""The name of the analyzers to run by the pipelines. If empty, it means all of
    them. Possible values are PIIs, Secrets, Topics, Confidentiality, Exploits.
    """
    annotations: NotRequired[Dict[str, str]]
    r"""Annotations attached to the extraction."""
    anonymization: NotRequired[ScanrequestAnonymization]
    r"""How to anonymize the data. If deanonymize is true, then VariablSize is required."""
    bypass_hash: NotRequired[str]
    r"""In the case of a contentPolicy that asks for a confirmation, this is the
    hash you must send back to bypass the block. This is only useful when a
    content policy has been set or is evaluated remotely.
    """
    content_policy: NotRequired[str]
    r"""ContentPolicy allows to pass optional Rego content policy. If not set,
    The action is always Allow, and there cannot be any alerts raised etc
    If it is set, it will be run, and the final decision will be computed based
    on that policy.
    If the rego code does not start with package main, then the needed
    classic package definition and  acuvity imports will be added
    automatically.
    If the code starts with package main, then everything remains untouched.
    """
    extractions: NotRequired[List[ExtractionrequestTypedDict]]
    r"""The extractions to request."""
    keywords: NotRequired[List[str]]
    r"""The keywords found during classification."""
    messages: NotRequired[List[str]]
    r"""Messages to process and provide detections for. Use data in extractions for
    processing binary data.
    """
    minimal_logging: NotRequired[bool]
    r"""If true, the system will not log the contents that were scanned."""
    redactions: NotRequired[List[str]]
    r"""The redactions to perform if they are detected."""
    type: NotRequired[ScanrequestType]
    r"""The type of text."""


class Scanrequest(BaseModel):
    r"""This is a scan request."""

    access_policy: Annotated[Optional[str], pydantic.Field(alias="accessPolicy")] = None
    r"""AccessPolicy allows to pass optional Rego access policy. If not set,
    The action is always Allow,
    If it is set, it will be run, and the final decision will be computed based
    on that policy.
    If the rego code does not start with package main, then the needed
    classic package definition and  acuvity imports will be added
    automatically.
    If the code starts with package main, then everything remains untouched.
    """

    analyzers: Optional[List[str]] = None
    r"""The name of the analyzers to run by the pipelines. If empty, it means all of
    them. Possible values are PIIs, Secrets, Topics, Confidentiality, Exploits.
    """

    annotations: Optional[Dict[str, str]] = None
    r"""Annotations attached to the extraction."""

    anonymization: Optional[ScanrequestAnonymization] = (
        ScanrequestAnonymization.FIXED_SIZE
    )
    r"""How to anonymize the data. If deanonymize is true, then VariablSize is required."""

    bypass_hash: Annotated[Optional[str], pydantic.Field(alias="bypassHash")] = None
    r"""In the case of a contentPolicy that asks for a confirmation, this is the
    hash you must send back to bypass the block. This is only useful when a
    content policy has been set or is evaluated remotely.
    """

    content_policy: Annotated[Optional[str], pydantic.Field(alias="contentPolicy")] = (
        None
    )
    r"""ContentPolicy allows to pass optional Rego content policy. If not set,
    The action is always Allow, and there cannot be any alerts raised etc
    If it is set, it will be run, and the final decision will be computed based
    on that policy.
    If the rego code does not start with package main, then the needed
    classic package definition and  acuvity imports will be added
    automatically.
    If the code starts with package main, then everything remains untouched.
    """

    extractions: Optional[List[Extractionrequest]] = None
    r"""The extractions to request."""

    keywords: Optional[List[str]] = None
    r"""The keywords found during classification."""

    messages: Optional[List[str]] = None
    r"""Messages to process and provide detections for. Use data in extractions for
    processing binary data.
    """

    minimal_logging: Annotated[
        Optional[bool], pydantic.Field(alias="minimalLogging")
    ] = None
    r"""If true, the system will not log the contents that were scanned."""

    redactions: Optional[List[str]] = None
    r"""The redactions to perform if they are detected."""

    type: Optional[ScanrequestType] = None
    r"""The type of text."""
