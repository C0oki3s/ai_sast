"""Turn the verifier's reproduction into one clean, safe, display-ready proof of concept.

The model returns ordered steps, a script as one item per line, its language and
the expected result. Before anything is stored this module:

* undoes stand-in line breaks (``</n>``, ``<br>``, escaped ``\\n``) and markdown fences;
* redacts secrets line by line without cutting a script line in half, keeping
  placeholders such as ``$AUTH_TOKEN`` that the reader fills in;
* refuses scripts with destructive commands (the prompt asks for read-only proof);
* syntax-checks bash and Python without running them;
* adds the shebang and a ``TARGET_URL`` guard a bash script needs to run as pasted.

A script that fails a check is withheld (the steps are kept) and the reason is
recorded as an evidence gap, never shown as a broken script.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass

from plaidnox_sast.redaction import redact, redact_script
from plaidnox_sast.textlines import split_model_lines

MAX_STEPS = 6
MAX_SCRIPT_LINES = 60
MAX_SCRIPT_CHARS = 4000

_STEP_NUMBER = re.compile(r"^\s*(?:(?:step\s*)?\d+[.):]|[-*•])\s+", re.IGNORECASE)
_FENCE_LINE = re.compile(r"^\s*```[\w-]*\s*$")
_SHEBANG = re.compile(r"^#!")
_USES_TARGET_URL = re.compile(r"\$\{?TARGET_URL\b")
_GUARDS_TARGET_URL = re.compile(r"TARGET_URL(?::\?|=)")

# Commands a read-only proof never needs. Matching any of them withholds the script.
_DESTRUCTIVE = (
    (re.compile(r"\brm\s+-[a-zA-Z]*[rf]", re.IGNORECASE), "deletes files"),
    (re.compile(r"\b(?:mkfs|fdisk|shutdown|reboot|halt|poweroff)\b"), "changes the host"),
    (re.compile(r"\bdd\s+if="), "writes raw devices"),
    (re.compile(r":\s*\(\s*\)\s*\{"), "fork bomb"),
    (re.compile(r"\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"), "pipes a download into a shell"),
    (re.compile(r"\b(?:DROP|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA)\b", re.IGNORECASE), "drops data"),
    (re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE), "deletes data"),
    (re.compile(r"(?:-X\s*|--request\s+)DELETE\b"), "sends a DELETE request"),
    (re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s"), "opens a reverse shell"),
    (re.compile(r"/dev/tcp/"), "opens a raw socket"),
    (re.compile(r"\bchmod\s+[0-7]*777\b|\bchown\s+-R\b"), "changes permissions"),
    (re.compile(r"\bcrontab\b|authorized_keys"), "establishes persistence"),
)

_FENCE_LANGUAGE = {"bash": "bash", "http": "http", "python": "python", "javascript": "javascript"}


@dataclass(frozen=True, slots=True)
class ProofOfConcept:
    steps: tuple[str, ...]
    language: str  # bash | http | python | javascript | none
    script: str
    expected_result: str
    # Why a script the model returned is not shown; recorded as an evidence gap.
    withheld_reason: str = ""

    def markdown(self) -> str | None:
        """Steps, the fenced script and the expected result, as stored for the UI and PR comments."""

        parts: list[str] = []
        if self.steps:
            parts.append("### Steps to Reproduce")
            parts.append("\n".join(f"{index}. {step}" for index, step in enumerate(self.steps, 1)))
        if self.script:
            parts.append(f"```{_FENCE_LANGUAGE.get(self.language, '')}\n{self.script}\n```")
        if self.expected_result and (self.steps or self.script):
            parts.append(f"**Expected result:** {self.expected_result}")
        return "\n\n".join(parts) if parts else None


def build_proof_of_concept(
    *,
    steps: Iterable[str] = (),
    language: str = "",
    script_lines: Iterable[str] = (),
    expected_result: str = "",
    proof_plan: str = "",
    proof_of_concept: str = "",
) -> ProofOfConcept:
    """Structured fields win; the legacy ``proof_plan``/``proof_of_concept`` strings are the fallback."""

    clean_steps = _steps(list(steps) or _lines(proof_plan))
    lines = [line for item in script_lines for line in _lines(item)] or _lines(proof_of_concept)
    lang = (language or "").strip().lower()
    if lang not in {"bash", "http", "python", "javascript"}:
        lang = "bash" if any(line.strip() for line in lines) else "none"
    expected = _sentence(expected_result)

    script, reason = _script(lines, lang)
    return ProofOfConcept(
        steps=clean_steps,
        language=lang if script else "none",
        script=script,
        expected_result=expected,
        withheld_reason=reason,
    )


def _lines(text: str) -> list[str]:
    return split_model_lines(text)


def _steps(items: list[str]) -> tuple[str, ...]:
    steps: list[str] = []
    for item in items:
        for line in _lines(item):
            text = _STEP_NUMBER.sub("", line).strip()
            if not text or text.lower().startswith("### steps") or _FENCE_LINE.match(text):
                continue
            steps.append(redact(" ".join(text.split()))[:300])
    return tuple(steps[:MAX_STEPS])


def _sentence(text: str) -> str:
    value = " ".join(" ".join(split_model_lines(text)).split())
    value = re.sub(r"^\**expected result:?\**\s*", "", value, flags=re.IGNORECASE)
    return redact(value)[:300]


def _script(lines: list[str], language: str) -> tuple[str, str]:
    kept = [line.rstrip() for line in lines if not _FENCE_LINE.match(line)]
    # A whole script wrapped in single backticks (an inline-code habit of some models).
    if kept and kept[0].lstrip().startswith("`") and not kept[0].lstrip().startswith("```"):
        kept[0] = kept[0].lstrip().lstrip("`")
    if kept and kept[-1].endswith("`") and not kept[-1].endswith("```"):
        kept[-1] = kept[-1].rstrip("`")
    while kept and not kept[0].strip():
        kept.pop(0)
    while kept and not kept[-1].strip():
        kept.pop()
    if language == "none" or not kept:
        return "", ""

    script = redact_script("\n".join(kept))
    for pattern, what in _DESTRUCTIVE:
        if pattern.search(script):
            return "", f"Proof-of-concept script withheld: it {what}, and a proof must be read-only."
    if language == "bash":
        script = _bash_preamble(script)
    lines_out = script.split("\n")
    if len(lines_out) > MAX_SCRIPT_LINES or len(script) > MAX_SCRIPT_CHARS:
        return "", (
            f"Proof-of-concept script withheld: longer than {MAX_SCRIPT_LINES} lines or "
            f"{MAX_SCRIPT_CHARS} characters."
        )
    problem = _syntax_problem(script, language)
    if problem:
        return "", f"Proof-of-concept script withheld: {problem}"
    return script, ""


def _bash_preamble(script: str) -> str:
    lines = script.split("\n")
    if not _SHEBANG.match(lines[0]):
        lines.insert(0, "#!/usr/bin/env bash")
    if _USES_TARGET_URL.search(script) and not _GUARDS_TARGET_URL.search(script):
        at = 1
        while at < len(lines) and (lines[at].startswith("#") or lines[at].startswith("set ")):
            at += 1
        lines.insert(at, ': "${TARGET_URL:?set TARGET_URL to the application origin}"')
    return "\n".join(lines)


def _syntax_problem(script: str, language: str) -> str:
    """Parse, never run, the script. Returns a reason when it does not parse."""

    if language == "python":
        try:
            compile(script, "<proof-of-concept>", "exec")
        except SyntaxError as exc:
            return f"Python syntax error on line {exc.lineno}."
        return ""
    if language == "bash":
        bash = shutil.which("bash")
        if bash is None:
            return ""
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, script only parsed (-n), never executed
                [bash, "-n"], input=script, capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        if completed.returncode != 0:
            detail = (completed.stderr.strip().splitlines() or ["syntax error"])[-1]
            return f"bash syntax check failed ({detail.split(':', 1)[-1].strip()[:120]})."
    return ""
