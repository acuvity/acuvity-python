# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 Acuvity, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import List, Dict, Optional, TypeVar, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

try:
    import msgpack
    import msgpack.ext
    HAVE_MSGPACK = True
except ImportError:
    HAVE_MSGPACK = False

class AcuvityModel(BaseModel):
    """
    AcuvityModel is the base class for all models in the Acuvity API.
    It serves mainly as a marker that all of these classes are models which belong to us.
    However, we will also extend this with utility functions that are useful for all models.
    """
    @model_validator(mode="before")
    def convert_msgpack_timestamps(cls, values):
        """
        This validator runs before any other field-level validation.
        It converts any `msgpack.ext.Timestamp` in the model to a `datetime` object
        so that we can have normal datetim objects in the model and still use msgpack
        and json interchangeably.
        """
        if not HAVE_MSGPACK:
            return values
        else:
            # Iterate through all fields and check for `msgpack.ext.Timestamp`
            for field, value in values.items():
                if isinstance(value, msgpack.ext.Timestamp):
                    # values[field] = datetime.fromtimestamp(value.seconds + value.nanoseconds / 1e9)
                    values[field] = value.to_datetime()
            return values

AcuvityObject = TypeVar('AcuvityObject', bound=AcuvityModel)
RequestAcuvityObject = TypeVar('RequestAcuvityObject', bound=AcuvityModel)
ResponseAcuvityObject = TypeVar('ResponseAcuvityObject', bound=AcuvityModel)


class ElementalError(AcuvityModel):
    """
    ElementalError represents the model of an error
    """
    model_config = ConfigDict(strict=False)

    code: Optional[int] = Field(None, description="Optional error code.")
    description: str = Field(..., description="The error description.")
    subject: str = Field(..., description="The error subject.")
    title: str = Field(..., description="The error title.")
    data: Optional[Any] = Field(None, description="Optional additional error data.")
    trace: Optional[str] = Field(None, description="Optional error trace.")

class ApexInfo(AcuvityModel):
    """
    ApexInfo holds the well known URL and CA information for an apex for a namespace.

    Fields:
    - url: the URL of the Apex
    - CAs: the CA certificates that verify the certificates that this apex is serving
    """
    model_config = ConfigDict(strict=False)

    url: str = Field(..., description="The URL of the Apex.")
    cas: Optional[str] = Field(None, description="The CA certificates that verify the certificates that this apex is serving.", alias="CAs")


class PrincipalApp(AcuvityModel):
    """
    PrincipalApp represents the model of a principalapp

    Fields:
    - labels: The list of labels attached to an application request.
    - name: The name of the application.
    - tier: The tier of the application request.
    """
    model_config = ConfigDict(strict=False)

    labels: Optional[List[str]] = Field(None, description="The list of labels attached to an application request.")
    name: Optional[str] = Field(None, description="The name of the application.")
    tier: Optional[str] = Field(None, description="The tier of the application request.")


class PrincipalUser(AcuvityModel):
    """
    PrincipalUser represents the model of a principaluser

    Fields:
    - name: Identification bit that will be used to identify the origin of the request.
    """
    name: str = Field(..., description="Identification bit that will be used to identify the origin of the request.")


class Principal(AcuvityModel):
    """
    Principal represents the model of a principal
    """
    model_config = ConfigDict(strict=False)

    app : Optional[PrincipalApp] = Field(None, description="The application principal information if type is App.")
    authType: str = Field(..., description="The type of authentication.")
    claims: Optional[List[str]] = Field(None, description="List of claims extracted from the user query.")
    team: Optional[str] = Field(None, description="The team that was used to authorize the request.")
    tokenName: str = Field(..., description="The name of the token, if any.")
    type: str = Field(..., description="The type of principal.")
    user: Optional[PrincipalUser] = Field(None, description="The user principal information if type is User.")


class AlertEvent(AcuvityModel):
    """
    AlertEvent represents the model of a alertevent
    """
    model_config = ConfigDict(strict=False)

    alertDefinition: str = Field(..., description="The name of the alert definition that triggered the alert event.")
    alertDefinitionNamespace: str = Field(..., description="The namespace of the alert definition.")
    principal: Principal = Field(..., description="The principal of the object.")
    provider: str = Field(..., description="The provider used that the alert came from.")
    timestamp: Optional[datetime] = Field(None, description="When the alert event was raised.")


class Modality(AcuvityModel):
    """
    Modality represents the model of a modality
    """
    model_config = ConfigDict(strict=False)

    group: str = Field(..., description="The group of data.")
    type: str = Field(..., description="The type of data.")


class TextualDetection(AcuvityModel):
    """
    TextualDetection represents the model of a textualdetection
    """
    model_config = ConfigDict(strict=False)

    end: int = Field(..., description="The end position of the detection.")
    key: str = Field(..., description="The key that is used in the name's place, If empty, a sequence of X's are used.")
    name: Optional[str] = Field(None, description="The name of the detection.")
    score: float = Field(..., description="The confidence score of the detection.")
    start: int = Field(..., description="The start position of the detection.")
    type: str = Field(..., description="The type of detection.")


class Extraction(AcuvityModel):
    """
    Extraction represents the model of a extraction
    """
    model_config = ConfigDict(strict=False)

    PIIs: Optional[Dict[str, float]] = Field(None, description="The PIIs found during classification.")
    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the extraction.")
    categories: Optional[List[Modality]] = Field(None, description="The categories are remapping of the modalities in a more human friendly way.")
    confidentiality: Optional[float] = Field(None, description="The level of general confidentiality of the input.")
    data: str = Field(..., description="The data extracted.")
    detections: Optional[List[TextualDetection]] = Field(None, description="The detections found while applying policies.")
    exploits: Optional[Dict[str, float]] = Field(None, description="The various exploits attempts.")
    hash: str = Field(..., description="The hash of the extraction.")
    intent: Optional[Dict[str, float]] = Field(None, description="The estimated intent embodied into the text.")
    internal: Optional[bool] = Field(None, description="If true, this extraction is for internal use only.")
    keywords: Optional[Dict[str, float]] = Field(None, description="The keywords found during classification.")
    label: Optional[str] = Field(None, description="A means of distinguishing what was extracted, such as prompt, input file or code.")
    languages: Optional[Dict[str, float]] = Field(None, description="The language of the classification.")
    luaID: Optional[str] = Field(None, description="An internal field for lua code. it is ignored by the API.")
    modalities: Optional[List[Modality]] = Field(None, description="The modalities of data detected in the data.")
    redactions: Optional[List[TextualDetection]] = Field(None, description="The redactions that has been performed.")
    relevance: Optional[float] = Field(None, description="The level of general organization relevance of the input.")
    secrets: Optional[Dict[str, float]] = Field(None, description="The secrets found during classification.")
    topics: Optional[Dict[str, float]] = Field(None, description="The topic of the classification.")


class Latency(AcuvityModel):
    """
    Latency represents the model of a latency
    """
    model_config = ConfigDict(strict=False)

    accessPolicy: int = Field(..., description="How much time it took to run the access policy in nanoseconds.")
    analysis: int = Field(..., description="How much time it took to run content analysis in nanoseconds.")
    assignPolicy: int = Field(..., description="How much time it took to run the assign policy in nanoseconds.")
    contentPolicy: int = Field(..., description="How much time it took to run content policy in nanoseconds.")
    extraction: int = Field(..., description="How much time it took to run input or output extraction in nanoseconds.")


class ValidateResponse(AcuvityModel):
    """
    ValidateResponse represents the model of a response to a validate API call
    """
    model_config = ConfigDict(strict=False)

    ID: Optional[str] = Field(None, description="The identifier of the object.")
    alerts: Optional[List[AlertEvent]] = Field(None, description="List of alerts that got raised during the policy resolution.")
    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the log.")
    decision: str = Field(..., description="Tell what was the decision about the data.")
    extractions: List[Extraction] = Field(..., description="The extractions to log.")
    hash: str = Field(..., description="The hash of the input.")
    importHash: Optional[str] = Field(None, description="The hash of the structure used to compare with new import version.")
    importLabel: Optional[str] = Field(None, description="The user-defined import label that allows the system to group resources from the same import operation.")
    latency: Latency = Field(..., description="Information about latency of various stage of request and response.")
    namespace: Optional[str] = Field(None, description="The namespace of the object.")
    pipelineName: str = Field(..., description="The name of the particular pipeline that extracted the text.")
    principal: Principal = Field(..., description="The principal of the object.")
    provider: str = Field(..., description="The provider to use.")
    reasons: Optional[List[str]] = Field(None, description="The various reasons returned by the policy engine.")
    time: datetime = Field(..., description="Set the time of the message request.")
    type: str = Field(..., description="The type of text.")


class ExtractionRequest(AcuvityModel):
    """
    ExtractionRequest contains the data of an extraction request..
    """
    model_config = ConfigDict(strict=False)

    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the extraction.", alias="Annotations")
    content: str = Field(..., description="The data extracted.", alias="Content")
    label: Optional[str] = Field(None, description="A means of distinguishing what was extracted, such as prompt, input file or code.", alias="Label")


class AnonymizationEnum(str, Enum):
    """
    AnonymizationEnum represents all the valid values for the anonymization field in a ValidateRequest.
    """
    fixedSize = "FixedSize"
    variableSize = "VariableSize"


class ValidateRequestTypeEnum(str, Enum):
    """
    ValidateRequestTypeEnum represents all the valid values for the type field in a ValidateRequest.
    """
    input = "Input"
    output = "Output"


class ValidateRequest(AcuvityModel):
    """
    ValidateRequest represents the model of a request to the validate API
    """
    model_config = ConfigDict(strict=False)

    _managed: bool = PrivateAttr(default=False)

    annotations: Optional[Dict[str, str]] = Field(None, description="Annotations attached to the log.")
    anonymization: Optional[AnonymizationEnum] = Field(None, description="Anonymization values to use. This can be FixedSize or VariableSize.")
    extractions: Optional[List[ExtractionRequest]] = Field(None, description="The extractions to process for this request.")
    messages: Optional[List[str]] = Field(None, description="Messages to process and provide detections for. These are additive to the set extractions. This is a shortcut for ExtractionRequest.content essentially.")
    type: ValidateRequestTypeEnum = Field(..., description="The type of validation request this is. This can be Input or Output.")
    analyzers: Optional[List[str]] = Field(None, description="These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use '+' to include an analyzer and '-' to exclude an analyzer. For example, ['+pii_detector', '-ner_detector'] will include the PII detector and exclude the NER detector.")
    keywords: Optional[List[str]] = Field(None, description="The keywords to try to detect for in the request data.")
    redactions: Optional[List[str]] = Field(None, description="The redactions to use: the strings need to match the names of the textual detections. For example, if a PII location was detected and you want to redact it, you need to use 'location' for the redaction as this is its textual detection name.")
    minimalLogging: Optional[bool] = Field(None, description="If true, only minimal logging will be done which essentially skips logging the request data.")
    contentPolicy: Optional[str] = Field(None, description="ContentPolicy allows to pass optional Rego content policy. If not set, The action is always Allow, and there cannot be any alerts raised etc If it is set, it will be run, and the final decision will be computed based on that policy. If the rego code does not start with 'package main', then the needed classic package definition and  acuvity imports will be added automatically. If the code starts with `package main`, then everything remains untouched.")
    bypassHash: Optional[str] = Field(None, description="In the case of a contentPolicy that asks for a confirmation, this is the hash you must send back to bypass the block. This is only useful when a content policy has been set.", alias="bypass")

    @model_validator(mode='after')
    def additional_validation_check(self) -> 'ValidateRequest':
        # redactions and contentPolicy are mutual exclusive
        red = self.redactions
        cp = self.contentPolicy
        if red is not None and len(red) > 0 and cp is not None and cp != "":
            raise ValueError("if redactions are set, you cannot use contentPolicy and vice versa")

        # on managed requests you cannot set a lot of fields
        if (self._managed and (
            (self.analyzers is not None and len(self.analyzers) > 0) or
            (self.keywords is not None and len(self.keywords) > 0) or
            (self.redactions is not None and len(self.redactions) > 0) or
            (self.minimalLogging is not None) or
            (self.contentPolicy is not None and self.contentPolicy != "") or
            (self.bypassHash is not None and self.bypassHash != "")
        )):
            raise ValueError("You cannot set analyzers, keywords, redactions, minimalLogging, contentPolicy or bypass when using backend policies")

        return self
