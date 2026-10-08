"""Split model-written text into lines, undoing the line-break stand-ins models use.

Models sometimes write a line break as ``</n>``, ``<br>`` or a literal escaped
``\\n`` instead of a newline. An escaped ``\\n`` is only treated as a line break
when it sits outside quotes, so ``printf 'a\\nb'`` keeps its meaning.
"""

from __future__ import annotations

import re

_LINE_BREAK_TOKENS = re.compile(r"</n>|<br\s*/?>|</br>", re.IGNORECASE)


def split_model_lines(text: str) -> list[str]:
    value = _LINE_BREAK_TOKENS.sub("\n", str(text or "").replace("\r\n", "\n").replace("\r", "\n"))
    if "\n" not in value and "\\n" in value:
        value = _unescape_newlines_outside_quotes(value)
    return value.split("\n")


def _unescape_newlines_outside_quotes(value: str) -> str:
    out: list[str] = []
    quote = ""
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(value):
                out.append(value[index : index + 2])
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char == "\\" and value[index + 1 : index + 2] == "n":
            out.append("\n")
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)
