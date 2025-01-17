import os

from dataclasses import dataclass
from typing import Dict, List, Optional

from acuvity.guard.config import GuardConfig, Guard, Threshold, Match
from acuvity.guard.constants import GuardName
from acuvity.models.scanresponse import Scanresponse
from acuvity.models.extraction import Extraction
from acuvity.models.textualdetection import Textualdetection, TextualdetectionType

@dataclass(frozen=False)
class ResultMatch:
    """Result of a single check operation."""
    response_match: bool
    guard_name: GuardName
    actual_value: float
    threshold: Threshold = Threshold("> 0.0")
    categories_count: int = 0
    detections_count: int = 0
    textual_detections: list[Textualdetection] | None = None

@dataclass(frozen=False)
class ResultMatches:
    """Result of processing multiple checks or a configuration."""
    response_match: bool
    matched_checks: list[ResultMatch]
    all_checks: list[ResultMatch]

class ScanResponseMatch:
    """
    Wrapper for Scanresponse to add functionality for checking guards.
    """
    def __init__(
            self,
            scan_response: Scanresponse,
            guard_config: GuardConfig,
            num_messages: int,
        ):
        self._guard_config = guard_config
        self.scan_response = scan_response
        self._num_messages = num_messages
        if self._guard_config is None:
            raise ValueError("No guard configuration was passed or available in the instance.")

    def no_match_result(self, guard_name: GuardName, actual_value: float = 1.0, categories_count: int = 0) -> ResultMatch:
        return ResultMatch(
            response_match=False,
            guard_name=guard_name,
            threshold=Threshold("> 0.0"),
            actual_value=actual_value,
            categories_count=categories_count,
        )

    def extract_textual_detection(
            self,
            type: TextualdetectionType,
            detections: list[Textualdetection] | None,
            categories_count: int,
            guard: Guard,
        ) -> ResultMatch:
        """
        Extract the detections matching a specific type of TextualdetectionType, submatch specifies the category. For example, we can ask
        PII with a submatch of Email.
        TODO: This should be enumerated in ScanResponse API sepc.
        """
        if not detections:
            return self.no_match_result(guard.name, categories_count=categories_count)

        response_match = True

        # We did not find as many categories so mark it as not a match.
        if guard.count_threshold and categories_count < guard.count_threshold:
            print(f"Count threshold for categories not met: {categories_count} < {guard.count_threshold} ({guard})")
            response_match = False

        detections_count = 0
        detections_subset = []
        # Initialize counters for thresholding.
        count_thresholds = {}
        for m in guard.matches.keys():
            count_thresholds[m] = 0

        print(f"Checking {len(detections)} detections for {type}")
        print(f"count_thresholds: {count_thresholds}")
        print(f"matches: {guard.matches}")

        for detection in detections:
            if detection.type != type:
                continue
            if len(guard.matches) != 0:
                if detection.name:
                    if detection.name not in guard.matches:
                        continue
                    if detection.score and not guard.matches[detection.name].threshold.compare(detection.score):
                        print(f"Score threshold not met: {detection.score} < {guard.matches[detection.name].threshold}")
                        response_match = False
                        continue

            count_thresholds[detection.name] += 1
            detections_count += 1
            detections_subset.append(detection)

        # Compare the count thresholds for specific categories.
        for mname, mmatch in guard.matches.items():
            print(f"Checking {mname} with {mmatch}")

            if mmatch.count_threshold and count_thresholds[mname] < mmatch.count_threshold:
                print(f"Count threshold for {mname} not met: {count_thresholds[mname]} < {mmatch.count_threshold}")
                response_match = False

        return ResultMatch(
                response_match=response_match,
                guard_name=guard.name,
                threshold=guard.threshold,
                actual_value=1.0,
                categories_count=categories_count,
                detections_count=detections_count,
                textual_detections=detections_subset
            )

    def _find_textual_detection_match(
            self,
            extraction: Extraction,
            lookup: Dict[str, float] | None,
            guard: Guard,
            type: TextualdetectionType,
        ) -> ResultMatch:
        """
        Find the textual detections match for a specific type of TextualdetectionType, submatch specifies the category. For example, we can ask
        PII with a submatch of Email.
        TODO: This should be enumerated in ScanResponse API sepc.
        """
        if not lookup or len(lookup) == 0:
            return self.no_match_result(guard.name)

        return self.extract_textual_detection(type, extraction.detections, len(lookup), guard)

    def _find_detection_match(self, lookup: Dict[str, float] | None, key: str, guard: Guard) -> ResultMatch:
        """
        Find the detections match for a specific type of guard type.
        """
        if not lookup:
            return self.no_match_result(guard.name)

        actual_value = lookup.get(key)
        if actual_value:
            if guard.threshold.compare(actual_value):
                return ResultMatch(
                    response_match=True,
                    guard_name=guard.name,
                    threshold=guard.threshold,
                    actual_value=actual_value
                    )
        else:
            actual_value = 0.0
        return self.no_match_result(guard.name, actual_value=actual_value)

    def find(
            self,
            extraction: Extraction,
            name: GuardName,
            guard: Optional[Guard] = None,
            submatch: Optional[str] = None,
        ) -> ResultMatch:
        """
        Find the detections matching a specific guard and additionally a submatch for that category.
        TODO: This should be enumerated in ScanResponse API sepc.
        """

        # Condition the input so helper functions are simpler.
        if guard:
            if submatch:
                raise ValueError("Configuration and Submatch not supported together.")
        else:
            matches = {}
            if submatch:
                matches = {
                    submatch: Match(
                        threshold=Threshold("> 0.0"),
                    )
                }
            guard = Guard(
                name=name,
                matches=matches,
                threshold=Threshold("> 0.0"),
            )

        # Actually find ..
        if name == GuardName.LANGUAGE:
            if not extraction.languages:
                return self.no_match_result(guard.name)
            count = 0
            for language in extraction.languages:
                if guard.matches and not guard.matches.get(language):
                    continue
                count += 1
            if count > 0:
                return ResultMatch(
                    response_match=True,
                    guard_name=name,
                    threshold=guard.threshold,
                    actual_value=1.0,
                    detections_count=count
                )
            return self.no_match_result(guard.name)
        elif name == GuardName.MODALITY:
            if not extraction.modalities:
                return self.no_match_result(guard.name)
            count = 0
            for modality in extraction.modalities:
                if guard.matches and not guard.matches.get(modality):
                    continue
                count += 1
            if count > 0:
                return ResultMatch(
                    response_match=True,
                    guard_name=name,
                    threshold=guard.threshold,
                    actual_value=1.0,
                    detections_count=count
                )
            return self.no_match_result(guard.name)
        elif name == GuardName.PROMPT_INJECTION or name == GuardName.JAILBREAK or name == GuardName.MALICIOUS_URL:
            return self._find_detection_match(extraction.exploits, str(name), guard)
        elif name == GuardName.TOXIC or name == GuardName.BIASED or name == GuardName.HARMFUL_CONTENT:  # single mattch, we need to trigger analyzer for biased "+biased"
            return self._find_detection_match(extraction.topics, "content/" + str(name), guard)
        elif name == GuardName.PII_DETECTOR: # multiple
            return self._find_textual_detection_match(extraction, extraction.pi_is, guard, TextualdetectionType.PII)
        elif name == GuardName.SECRETS_DETECTOR: # multiple
            return self._find_textual_detection_match(extraction, extraction.secrets, guard, TextualdetectionType.SECRET)
        elif name == GuardName.KEYWORD_DETECTOR: # multiple
            return self._find_textual_detection_match(extraction, extraction.keywords, guard, TextualdetectionType.KEYWORD)

    def findany(
            self,
            name: GuardName,
            submatch: Optional[str] = None,
            file_index: Optional[int] = None,
            text_index: Optional[int] = None,
        ) -> ResultMatch:
        """
        Find any match across any response matching a guard name.
        """
        if not self.scan_response.extractions:
            return self.no_match_result(name)

        if file_index or text_index:
            lookup_index = 0
            if text_index:
                lookup_index = text_index
            elif file_index:
                lookup_index = self._num_messages + file_index

            if lookup_index < len(self.scan_response.extractions):
                extraction = self.scan_response.extractions[lookup_index]
                for guard in self._guard_config.parsed_guards:
                    if guard.name != name:
                        continue
                    m = self.find(extraction, guard.name, guard, submatch)
                    if m.response_match:
                        return m
        else:
            for extraction in self.scan_response.extractions:
                for guard in self._guard_config.parsed_guards:
                    if guard.name != name:
                        continue
                    m = self.find(extraction, guard.name, guard, submatch)
                    if m.response_match:
                        return m

        return self.no_match_result(name)

    def findall(self) -> List[ResultMatches]:
        """
        Find all matches in scan reponse based on a config.
        """
        matches = []
        if not self.scan_response.extractions:
            return matches

        for extraction in self.scan_response.extractions:
            match = []
            all_match = []
            for guard in self._guard_config.parsed_guards:
                m = self.find(extraction, guard.name, guard)
                if m.response_match:
                    match.append(m)
                all_match.append(m)
            matches.append(ResultMatches(
                response_match=len(match) == len(all_match),
                matched_checks=match,
                all_checks=all_match
            ))

        return matches