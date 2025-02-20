# pylint: disable=protected-access

import base64
import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Union

from acuvity.guard.config import Guard, GuardConfig, GuardName
from acuvity.models import (
    Analyzer,
    Anonymization,
    Extractionrequest,
    Scanrequest,
    Type,
)
from acuvity.response.match import ScanResponseMatch
from acuvity.sdkconfiguration import SDKConfiguration
from acuvity.utils.logger import get_default_logger

from .apex import Apex

logger = get_default_logger()




class ApexExtended(Apex):
    def __init__(self, sdk_config: SDKConfiguration) -> None:
        super().__init__(sdk_config)
        self._available_analyzers: Optional[List[Analyzer]] = None

    def list_available_guards(self) -> List[str]:
        """
        list_available_guards: returns a list of all available guards that can be detected.
        """
        return GuardName.values()

    def list_detectable_secrets(self) -> List[str]:
        """
        list_detectable_secrets: returns a list of all available secrets that can be detected.
        """
        detectable_secrets: List[str] = []
        if self._available_analyzers is None:
            self._available_analyzers = self.list_analyzers()
        for analyzer in self._available_analyzers:
            if analyzer.detectors:
                detectable_secrets_local = [
                    str(detector.name)
                    for detector in analyzer.detectors
                    if detector.group == "Secrets"
                ]
                detectable_secrets.extend(detectable_secrets_local)
        return sorted(list(set(detectable_secrets)))

    def list_detectable_piis(self) -> List[str]:
        """
        list_detectable_piis: returns a list of all available Piis that can be detected.
        """
        detectable_piis: List[str] = []
        if self._available_analyzers is None:
            self._available_analyzers = self.list_analyzers()
        for analyzer in self._available_analyzers:
            if analyzer.detectors:
                detectable_piis_local = [
                    str(detector.name)
                    for detector in analyzer.detectors
                    if detector.group == "PIIs"
                ]
                detectable_piis.extend(detectable_piis_local)
        return sorted(list(set(detectable_piis)))

    def scan(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        guard_config: Optional[Union[str, Path, Dict, List[Guard]]] = None,
    ) -> ScanResponseMatch:
        """
        scan() runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Scanresponse object on success, and raises different exceptions on failure.

        This function allows to use and try different analyzers and make use of the redaction feature.
        You can also run access policies and content policies by passing them as parameters.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.
        :param request_type: the type of the validation. This can be either Type.INPUT or Type.OUTPUT. Defaults to Type.INPUT. Use Type.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param redactions: the redactions that need to be redacted if detected. This arg cannot be used with guard_config.
        :param keywords: the keywords that need to be detected. This arg cannot be used with guard_config.
        :param guard_config: the guard config used to do the response eval for matches. If not provided, the default guard config will be used.
        """

        raw_scan_response = self.scan_request(request=self.__build_scan_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            redactions=redactions,
            keywords=keywords,
            guard_config=guard_config if guard_config is None else GuardConfig(guard_config),
        ))

        # always send a guard config to the ScanResponseMatch
        try:
            if guard_config:
                gconfig = GuardConfig(guard_config)
            else:
                gconfig = GuardConfig()
        except Exception as e:
            logger.debug("Error while processing the guard config")
            raise ValueError("Cannot process the guard config") from e

        return ScanResponseMatch(raw_scan_response, gconfig, files=files)

    async def scan_async(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        guard_config: Optional[Union[str, Path, Dict, List[Guard]]] = None,
    ) -> ScanResponseMatch:
        """
        scan_async() runs the provided messages (prompts) through the Acuvity detection engines and returns the results. Alternatively, you can run model output through the detection engines.
        Returns a Scanresponse object on success, and raises different exceptions on failure.

        This function allows to use and try different analyzers and make use of the redaction feature.
        You can also run access policies and content policies by passing them as parameters.

        :param messages: the messages to scan. These are the prompts that you want to scan. Required if no files or a direct request object are provided.
        :param files: the files to scan. These are the files that you want to scan. Required if no messages are provided. Can be used in addition to messages.        :param request_type: the type of the validation. This can be either Type.INPUT or Type.OUTPUT. Defaults to Type.INPUT. Use Type.OUTPUT if you want to run model output through the detection engines.
        :param annotations: the annotations to use. These are the annotations that you want to use. If not provided, no annotations will be used.
        :param analyzers: the analyzers to use. These are the analyzers that you want to use. If not provided, the internal default analyzers will be used. Use "+" to include an analyzer and "-" to exclude an analyzer. For example, ["+image-classifier", "-modality-detector"] will include the image classifier and exclude the modality detector. If any analyzer does not start with a '+' or '-', then the default analyzers will be replaced by whatever is provided. Call `list_analyzers()` and/or its variants to get a list of available analyzers.
        :param guard_config: the guard config used to do the response eval for matches. If not provided, the default guard config will be used.
        """
        raw_scan_response = await self.scan_request_async(request=self.__build_scan_request(
            *messages,
            files=files,
            request_type=request_type,
            annotations=annotations,
            redactions=redactions,
            keywords=keywords,
            guard_config=guard_config if guard_config is None else GuardConfig(guard_config),
        ))
        # always send a guard config to the ScanResponseMatch
        try:
            if guard_config:
                gconfig = GuardConfig(guard_config)
            else:
                gconfig = GuardConfig()
        except Exception as e:
            logger.debug("Error while processing the guard config")
            raise ValueError("Cannot process the guard config") from e

        return ScanResponseMatch(raw_scan_response, gconfig, files=files)

    def __build_scan_request(
        self,
        *messages: str,
        files: Union[Sequence[Union[str,os.PathLike]], os.PathLike, str, None] = None,
        request_type: Union[Type,str] = Type.INPUT,
        annotations: Optional[Dict[str, str]] = None,
        redactions: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        anonymization: Union[Anonymization, str, None] = None,
        guard_config: Optional[GuardConfig] = None,
    ) -> Scanrequest:
        request = Scanrequest.model_construct()

        # if guard_config is given, the keywords and redactions args must not be given.
        if guard_config and (keywords or redactions):
            raise ValueError("Cannot specify keywords or redactions in scan args when using guard config. Please use only one.")

        # messages must be strings
        for message in messages:
            if not isinstance(message, str):
                raise ValueError(f"messages must be strings but was {type(message)}")
        if len(messages) == 0 and files is None:
            raise ValueError("no messages and no files provided")
        if len(messages) > 0:
            request.messages = list(messages)

        # files must be a list of strings (or paths) or a single string (or path)
        extractions: List[Extractionrequest] = []
        if files is not None:
            process_files: List[Union[os.PathLike, str]] = []
            if isinstance(files, str):
                process_files.append(files)
            elif isinstance(files, os.PathLike):
                process_files.append(files)
            elif isinstance(files, Iterable):
                for file in files:
                    if not isinstance(file, str) and not isinstance(file, os.PathLike):
                        raise ValueError("files must be strings or paths")
                    process_files.append(file)
            else:
                raise ValueError("files must be strings or paths")
            for process_file in process_files:
                with open(process_file, 'rb') as opened_file:
                    file_content = opened_file.read()
                    # base64 encode the file content and then append
                    extractions.append(Extractionrequest(
                        data=base64.b64encode(file_content).decode("utf-8"),
                    ))
        if len(extractions) > 0:
            request.extractions = extractions

        # request_type must be either "Input" or "Output"
        if isinstance(request_type, Type):
            request.type = request_type
        elif isinstance(request_type, str):
            if request_type not in ("Input", "Output"):
                raise ValueError("request_type must be either 'Input' or 'Output'")
            request.type = Type(request_type)
        else:
            raise ValueError("type must be a 'str' or 'Type'")

        # annotations must be a dictionary of strings
        if annotations is not None:
            if not isinstance(annotations, dict):
                raise ValueError("annotations must be a dictionary")
            for key, value in annotations.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise ValueError("annotations must be strings")
            request.annotations = annotations

        # now here check the guard config and parse it for the redaction and keywords.
        if guard_config:
            keywords = guard_config.keywords
            redactions = guard_config.redaction_keys

        # anonymization must be "FixedSize" or "VariableSize"
        if anonymization is not None:
            if isinstance(anonymization, Anonymization):
                request.anonymization = anonymization
            elif isinstance(anonymization, str):
                if anonymization not in ("FixedSize", "VariableSize"):
                    raise ValueError("anonymization must be 'FixedSize' or 'VariableSize'")
                request.anonymization = Anonymization(anonymization)
            else:
                raise ValueError("anonymization must be a 'str' or 'Anonymization'")

        # redactions must be a list of strings
        if redactions is not None:
            if not isinstance(redactions, List):
                raise ValueError("redactions must be a list")
            for redaction in redactions:
                if not isinstance(redaction, str):
                    raise ValueError("redactions must be strings")
            request.redactions = redactions

        # keywords must be a list of strings
        if keywords is not None:
            if not isinstance(keywords, List):
                raise ValueError("keywords must be a list")
            for keyword in keywords:
                if not isinstance(keyword, str):
                    raise ValueError("keywords must be strings")
            request.keywords = keywords

        return request
