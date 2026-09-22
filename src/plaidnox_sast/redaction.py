"""Single secret-redaction gateway shared by every provider boundary.

Every payload sent to a generative or research provider must pass through
this module first, so no call site can accidentally skip redaction.
"""

from __future__ import annotations

import re
from typing import Any

_MONGO_URI = re.compile(r"mongodb(?:\+srv)?://[^\s\"'`]+", re.IGNORECASE)
_API_KEY = re.compile(r"\b(?:sk|rk)-[A-Za-z0-9_-]{10,}\b")
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_BEARER_TOKEN = re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b")


def redact(value: str) -> str:
    value = _MONGO_URI.sub("<redacted-mongodb-uri>", value)
    value = _API_KEY.sub("<redacted-api-key>", value)
    value = _AWS_ACCESS_KEY.sub("<redacted-aws-access-key>", value)
    value = _BEARER_TOKEN.sub("<redacted-bearer-token>", value)
    return value


def redact_payload(value: Any) -> Any:
    """Recursively redact every string leaf in a JSON-shaped payload."""

    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {key: redact_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_payload(item) for item in value)
    return value
