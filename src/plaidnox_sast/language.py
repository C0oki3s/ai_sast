"""English-only check for model-written text that people read.

Some models (notably the GLM family) drift into Chinese or emit stray symbols
mid-answer. Every natural-language field shown to people must be English. This
module finds text that is not: letters from non-Latin scripts (Chinese, Japanese,
Korean, Cyrillic, Arabic, Hebrew, Greek, Thai, Indic, ...), full-width forms,
garbled encodings (mojibake such as ``Ã©`` or ``â€``), the replacement character,
private-use and invisible formatting characters, and emoji.

Text inside backticks is code quoted from the repository and is not checked, so
an identifier or string literal from a non-English codebase stays allowed in
prose fields that quote it.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

_CODE_SPAN = re.compile(r"```.*?```|`[^`\n]*`", re.DOTALL)
_MOJIBAKE = re.compile(r"Ã[\x80-\xbf]|Â[\x80-\xbf]|â€|ï¿½")
# Punctuation and symbols that are normal in English technical writing.
_ALLOWED_SYMBOLS = frozenset("“”‘’–—…•·→←↔⇒≤≥≠±×÷°§©®™€£¥¢µ")
_ALLOWED_INVISIBLE = frozenset("\n\t\r")


@dataclass(frozen=True, slots=True)
class LanguageProblem:
    field: str
    reason: str
    sample: str

    def describe(self) -> str:
        return f"{self.field}: {self.reason} ({self.sample!r})"


def text_problem(value: str, *, code: bool = False) -> tuple[str, str] | None:
    """The first reason ``value`` is not clean English, with the offending sample."""

    text = value if code else _CODE_SPAN.sub(" ", value)
    mojibake = _MOJIBAKE.search(text)
    if mojibake:
        return "garbled character encoding", text[max(0, mojibake.start() - 10) : mojibake.end() + 10]
    for index, char in enumerate(text):
        if char.isascii():
            if char.isprintable() or char in _ALLOWED_INVISIBLE:
                continue
            return "control character", repr(char)
        reason = _non_english_reason(char)
        if reason:
            return reason, text[max(0, index - 10) : index + 10]
    return None


def _non_english_reason(char: str) -> str | None:
    if char in _ALLOWED_SYMBOLS:
        return None
    if char == "�":
        return "replacement character"
    category = unicodedata.category(char)
    if category in {"Cc", "Cf"}:
        return "invisible formatting character"
    if category in {"Co", "Cs", "Cn"}:
        return "unassigned or private-use character"
    if category.startswith("L"):
        name = unicodedata.name(char, "")
        # Latin letters with accents (café, naïve) are English loanwords and names.
        return None if name.startswith("LATIN ") else "non-English letters"
    if category.startswith("N"):
        return None if unicodedata.name(char, "").startswith(("SUPERSCRIPT", "SUBSCRIPT", "VULGAR")) else (
            "non-English digits"
        )
    if category == "So":
        return "emoji or pictograph"
    if category.startswith("P") or category.startswith("S"):
        name = unicodedata.name(char, "")
        if "FULLWIDTH" in name or "IDEOGRAPHIC" in name or name.startswith(("CJK", "HALFWIDTH")):
            return "non-English punctuation"
        return None
    return None


def check_fields(fields: Mapping[str, object], *, code_fields: Iterable[str] = ()) -> list[LanguageProblem]:
    """Problems across named fields; a field may hold a string or a list of strings."""

    code = set(code_fields)
    problems: list[LanguageProblem] = []
    for name, value in fields.items():
        items = value if isinstance(value, list | tuple) else [value]
        for index, item in enumerate(items):
            if not isinstance(item, str) or not item:
                continue
            found = text_problem(item, code=name in code)
            if found:
                label = name if len(items) == 1 else f"{name}[{index}]"
                problems.append(LanguageProblem(label, found[0], found[1]))
                break
    return problems
