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
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_PROVIDER_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|"
    r"sk_(?:live|test)_[A-Za-z0-9]{12,}|AIza[A-Za-z0-9_-]{30,})\b",
    re.IGNORECASE,
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?im)(\b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"client[_-]?secret|access[_-]?key|credential)[\w.-]*\b\s*[:=]\s*)"
    r"([^\r\n]+)"
)


def redact(value: str) -> str:
    value = _PEM_PRIVATE_KEY.sub("<redacted-private-key>", value)
    value = _CREDENTIAL_ASSIGNMENT.sub(r"\1<redacted-credential>", value)
    value = _JWT.sub("<redacted-jwt>", value)
    value = _PROVIDER_TOKEN.sub("<redacted-provider-token>", value)
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
