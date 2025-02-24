import pytest
from detectors_examples import EXAMPLES
from helpers import verify_match_details, save_prompts_to_files


class TestApexFunctions:
    @pytest.fixture(autouse=True)
    def load_setup_fixtures(self, init_apex, tmp_test_dir):
        self.apex = init_apex
        self.tmp_dir = tmp_test_dir

    @pytest.mark.parametrize("input", ["messages", "files"])
    def test_scan_method(self, input):
        test_prompts = [
            EXAMPLES["prompt_injection"],
            EXAMPLES["jailbreak"],
            EXAMPLES["pii_detector"],
        ]
        guard_json = {
            "guardrails": [
                {"name": "jailbreak"},
                {"name": "prompt_injection"},
                {"name": "pii_detector"},
            ]
        }

        if input == "files":
            file_paths = save_prompts_to_files(test_prompts, self.tmp_dir)
            res = self.apex.scan(files=file_paths, guard_config=guard_json)
        else:
            res = self.apex.scan(*test_prompts, guard_config=guard_json)
        verify_match_details(
            match_details=res.match_details[0],
            prompt=EXAMPLES["prompt_injection"],
            matched_guards=["prompt_injection"],
            non_matched_guards=["jailbreak", "pii_detector"],
        )
        verify_match_details(
            match_details=res.match_details[1],
            prompt=EXAMPLES["jailbreak"],
            matched_guards=["jailbreak"],
            non_matched_guards=["jailbreak", "prompt_injection"],
        )
        verify_match_details(
            match_details=res.match_details[2],
            prompt=EXAMPLES["pii_detector"],
            matched_guards=["pii_detector"],
            non_matched_guards=["jailbreak", "prompt_injection"],
        )

    def test_scan_prompt_and_files(self):
        test_prompt = EXAMPLES["prompt_injection"]
        file_paths = save_prompts_to_files([test_prompt], self.tmp_dir)
        guard_json = {"guardrails": [{"name": "prompt_injection"}]}
        res = self.apex.scan(test_prompt, files=file_paths, guard_config=guard_json)
        verify_match_details(
            res.match_details[0], test_prompt, ["prompt_injection"], []
        )
        verify_match_details(
            res.match_details[1], test_prompt, ["prompt_injection"], []
        )

    def test_scan_request_keywords_reductions(self):
        res = self.apex.scan_request(
            request={
                "messages": [EXAMPLES.get("keyword_detector")],
                "redactions": ["bluefin"],
                "keywords": ["bluefin"],
                "type": "Input",
            }
        )

        assert (
            "bluefin" not in res.extractions[0].data
        ), f"Keyword redaction failed in scan response {res}"
        assert res.extractions[0].keywords == {
            "bluefin": 1.0
        }, f"Keyword detection failed in scan response {res}"

    def test_list_analyzers(self):
        res = self.apex.list_analyzers()
        assert (
            isinstance(res, list) and len(res) > 0
        ), f"Unexpected list analyzers response {res}"

    def test_list_available_guards(self):
        res = self.apex.list_available_guards()
        assert (
            isinstance(res, list) and len(res) > 0
        ), f"Unexpected list_available_guards response {res}"

    def test_list_detectable_piis(self):
        res = self.apex.list_detectable_piis()
        assert (
            isinstance(res, list) and len(res) > 0
        ), f"Unexpected list_detectable_piis response {res}"

    def test_list_detectable_secrets(self):
        res = self.apex.list_detectable_secrets()
        assert (
            isinstance(res, list) and len(res) > 0
        ), f"Unexpected list_detectable_secrets response {res}"
