import pytest
from helpers import create_simple_guard, verify_match_details, verify_guard_match
from detectors_examples import EXAMPLES


class TestGuardrails:
    @pytest.fixture(autouse=True)
    def load_setup_fixtures(self, init_apex, get_guards, tmp_test_dir):
        self.apex = init_apex
        self.guards = get_guards
        self.tmp_dir = tmp_test_dir

    @pytest.mark.parametrize("guard_format", ["json", "guard_object", "yaml"])
    def test_detector_guardrail(self, subtests, guard_format):
        for guard in self.guards:
            with subtests.test(f"veryfing {guard}"):
                if guard == "biased":
                    continue
                threshold = "> 0.1" if guard != "modality" else ">= 0.0"
                matches = {} if guard != "keyword_detector" else {"bluefin": None}
                guard_config = create_simple_guard(
                    guard,
                    threshold=threshold,
                    matches=matches,
                    guard_format=guard_format,
                    test_dir=self.tmp_dir,
                )
                response = self.apex.scan(EXAMPLES[guard], guard_config=guard_config)
                match_details = response.match_details[0]
                verify_match_details(match_details, EXAMPLES[guard], [guard], [])
                verify_guard_match(
                    match_details.matched_checks[0],
                    response_match="YES",
                    threshold=threshold,
                    match_values=list(matches.keys()),
                )

    @pytest.mark.parametrize("expected_result", ["matched", "not_matched"])
    @pytest.mark.parametrize(
        "detector, matches",
        [
            ("pii_detector", ["money_amount", "email_address"]),
            ("keyword_detector", ["bluefin", "apollo"]),
            ("secrets_detector", ["credentials", "aws_secret_key"]),
        ],
        ids=["piis", "keywords", "secrets"],
    )
    def test_count_threshold(self, expected_result, detector, matches):
        if expected_result == "matched":
            guard_matches = {matches[0]: None, matches[1]: None}
        else:
            guard_matches = {
                matches[0]: {"count_threshold": 2},
                matches[1]: {"count_threshold": 1},
            }
        guard_config = create_simple_guard(
            detector, count_threshold=2, matches=guard_matches, guard_format="json"
        )
        prompt = EXAMPLES.get(f"multiple_{detector}", "")
        res = self.apex.scan(
            prompt,
            guard_config=guard_config,
        )
        match_details = res.match_details[0]
        if expected_result == "matched":
            verify_match_details(match_details, prompt, [detector], [])
            verify_guard_match(
                match_details.matched_checks[0],
                response_match="YES",
                guard_name=detector,
                match_count=2,
                match_values=matches,
            )
        elif expected_result == "not_matched":
            verify_match_details(match_details, prompt, [], [detector])
            verify_guard_match(match_details.all_checks[0], "NO", detector)

    def test_keyword_and_reductions(self):
        keywords = ["bluefin", "apollo"]
        guard_json = {
            "guardrails": [
                {
                    "name": "keyword_detector",
                    "matches": {keywords[0]: {}, keywords[1]: {"redact": True}},
                },
                {
                    "name": "pii_detector",
                    "matches": {
                        "email_address": {"redact": True, "count_threshold": 2}
                    },
                },
            ]
        }
        prompt = EXAMPLES["keywords_and_pii"]
        res = self.apex.scan(prompt, guard_config=guard_json)
        expected_data = prompt.replace("apollo", "XXXXXX").replace(
            "aaa@gmail.com", "XXXXXXXXXXXXX"
        )
        match_details = res.match_details[0]
        verify_match_details(
            match_details, expected_data, ["keyword_detector"], ["pii_detector"]
        )
        verify_guard_match(
            match_details.matched_checks[0],
            response_match="YES",
            guard_name="keyword_detector",
            match_count=2,
            match_values=keywords,
        )
