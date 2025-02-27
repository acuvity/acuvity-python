from acuvity import Guard
from acuvity.response.result import Matches, GuardMatch
from typing import Optional
import yaml


def create_simple_guard(
    guard_name: str,
    threshold: str = "0",
    count_threshold: int = 0,
    matches: Optional[dict] = None,
    guard_format: str = "guard_object",
    test_dir: Optional[str] = None,
):
    matches = matches or {}
    if guard_format == "guard_object":
        return [
            Guard.create(
                guard_name,
                threshold=threshold,
                count_threshold=count_threshold,
                matches=matches,
            )
        ]
    json_config = {
        "guardrails": [
            {
                "name": guard_name,
                "threshold": threshold,
                "count_threshold": count_threshold,
                "matches": matches,
            }
        ]
    }
    if guard_format == "json":
        return json_config
    elif guard_format == "yaml":
        config_path = f"{test_dir}/config.yaml"
        with open(config_path, "w") as file:
            yaml.dump(json_config, file, default_flow_style=False, sort_keys=False)
        return config_path


def save_prompts_to_files(prompts: list, test_dir: str):
    file_paths = [f"{test_dir}/file_{i}.txt" for i in range(len(prompts))]
    for i, prompt in enumerate(prompts):
        with open(file_paths[i], "w") as file:
            file.write(prompt)
    return file_paths


def verify_match_details(
    match_details: Matches, prompt: str, matched_guards: list, non_matched_guards: list
):
    checks = {}
    checks["prompt"] = match_details.input_data == prompt
    checks["all_checks_count"] = len(match_details.all_checks) == len(
        matched_guards
    ) + len(non_matched_guards)
    checks["response_match"] = match_details.response_match.value == (
        "YES" if matched_guards else "NO"
    )

    checks["matched_checks_count"] = len(match_details.matched_checks) == len(
        matched_guards
    )
    checks["matched__checks_names"] = sorted(
        [check.guard_name.value for check in match_details.matched_checks]
    ) == sorted(matched_guards)

    failed_checks = [check for check, value in checks.items() if value == False]
    assert (
        not failed_checks
    ), f"Found failed checks {failed_checks} in match_details: {match_details}"


def verify_guard_match(
    guard_match: GuardMatch,
    response_match: str = "",
    guard_name: str = "",
    actual_value: Optional[int] = None,
    threshold: str = "",
    match_count: Optional[int] = None,
    match_values: Optional[list] = None,
):
    checks = {}
    if response_match:
        checks["response_match"] = guard_match.response_match.value == response_match
    if guard_name:
        checks["guard_name"] = guard_match.guard_name.value == guard_name
    if actual_value:
        checks["actual_value"] = guard_match.actual_value == actual_value
    if threshold:
        checks["threshold"] = guard_match.threshold == threshold
    if match_count:
        checks["match_count"] = guard_match.match_count == match_count
    if match_values:
        checks["match_values"] = sorted(guard_match.match_values) == sorted(
            match_values
        )

    failed_checks = [check for check, value in checks.items() if value == False]
    assert (
        not failed_checks
    ), f"Found failed checks {failed_checks} in guard: {guard_match}"
