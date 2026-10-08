"""English-only enforcement for model-written text people read."""

from __future__ import annotations

import json

import pytest
from test_ai import deep_candidate, finding, review_payload

from plaidnox_sast.ai import AIResponseError, PlaidNoxDeepHuntAgent, deep_hunt_language_problems
from plaidnox_sast.ai import _deep_hunt_result_from_response as parse
from plaidnox_sast.language import check_fields, text_problem
from plaidnox_sast.prompts import render_operation


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("攻击者可以读取所有用户的数据", "non-English letters"),
        ("The handler 将 user input into the query", "non-English letters"),
        ("Привет мир", "non-English letters"),
        ("Fullwidth（paren）", "non-English punctuation"),
        ("Done 🚀", "emoji or pictograph"),
        ("Ã©tÃ© garbled", "garbled character encoding"),
        ("zero​width", "invisible formatting character"),
        ("bell \x07 here", "control character"),
    ],
)
def test_non_english_text_is_detected(text: str, reason: str) -> None:
    found = text_problem(text)
    assert found is not None and found[0] == reason


@pytest.mark.parametrize(
    "text",
    [
        "Plain English with “quotes”, an em dash — and arrows → are fine.",
        "Names such as café or naïve keep their accents.",
        "Repository identifiers like `用户名` are quoted code and allowed.",
        "Use `execFile(\"ping\", [\"-c\", \"1\", host])` instead of `exec`; x² ≤ 3.",
    ],
)
def test_english_text_passes(text: str) -> None:
    assert text_problem(text) is None


def test_script_lines_are_checked_as_code_including_their_comments() -> None:
    problems = check_fields(
        {"script": ["#!/usr/bin/env bash", "# 发送请求", 'curl "$TARGET_URL"']}, code_fields={"script"}
    )
    assert [problem.field for problem in problems] == ["script[1]"]


def test_every_reader_field_of_a_verifier_answer_is_checked() -> None:
    payload = review_payload(
        business_impact="攻击者可以读取数据。",
        evidence_locations=[{"path": "app.js", "start_line": 2, "end_line": 4, "role": "source",
                             "tainted_value": "req.body.name", "summary": "数据进入"}],
    )
    problems = deep_hunt_language_problems(parse(_Response(payload)))
    assert [problem.field for problem in problems] == ["business_impact", "evidence_locations.summary"]


def test_the_verifier_is_asked_once_more_in_english_and_the_english_answer_is_kept(sample_repo) -> None:
    client = _Client([review_payload(message="该请求将用户数据传入渲染器。"), review_payload()])

    review = PlaidNoxDeepHuntAgent(client, model="test-model").review(sample_repo, deep_candidate(), finding())

    assert review.supported is True
    assert len(client.responses.requests) == 2
    correction = client.responses.requests[1]["input"][-1]["content"]
    assert "output_language_correction" in correction and "message: non-English letters" in correction


def test_a_verifier_that_keeps_answering_in_another_language_is_rejected(sample_repo) -> None:
    chinese = review_payload(message="该请求将用户数据传入渲染器。")
    client = _Client([chinese, chinese])

    with pytest.raises(AIResponseError, match="non-English text after a correction"):
        PlaidNoxDeepHuntAgent(client, model="test-model").review(sample_repo, deep_candidate(), finding())


def test_every_prompt_states_the_english_only_rule() -> None:
    from plaidnox_sast.assets import load_json
    from plaidnox_scm.prompts import render_operation as render_scm

    system, _ = render_operation("security_review", {"x": 1}, output_schema=load_json("schemas/deep_hunt_review.json"))
    scm_system, _ = render_scm("changed_file_review", {"x": 1})
    for prompt in (system, scm_system):
        assert "Output language: English only" in prompt
        assert "Never write Chinese, Japanese, Korean, or any other language" in prompt


class _Response:
    status = "completed"

    def __init__(self, payload: dict) -> None:
        self.output_text = json.dumps(payload)


class _Responses:
    def __init__(self, payloads: list[dict]) -> None:
        self.payloads = list(payloads)
        self.requests: list[dict] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return _Response(self.payloads.pop(0))


class _Client:
    def __init__(self, payloads: list[dict]) -> None:
        self.responses = _Responses(payloads)
