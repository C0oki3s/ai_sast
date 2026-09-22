"""Deterministic pre-AI ChangeRelevance gate.

Implements the field set from docs/PRODUCT_WORKSTREAMS.md's "Deterministic
change-relevance gate" section: a pure, rule-based classifier over a `Diff`
that decides whether generative review is required at all, and if so at
what minimum depth. No model call happens here.

Coverage note: the mandatory-escalation list in the plan names twelve
categories (authentication, authorization/tenancy, identity/session/token,
routes/controllers/middleware, data readers/writers, file/network/process/
cloud effects, security configuration, signing/crypto, credentials/secrets,
admin/payment/high-value workflows, state transitions/concurrency, prior
finding dependencies). This first pass implements path- and content-keyword
heuristics for security_control_changed and sensitive_material_changed,
which together cover authentication, authorization/session/token handling,
routes/middleware, security configuration, signing/crypto, and
credentials/secrets. Data readers/writers, file/network/process/cloud
effects, admin/payment workflows, state/concurrency, and prior-finding
dependencies need semantic (not just lexical) classification and are a
named Wave 2 refinement, not silently claimed as covered here.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from plaidnox_sast.ai import _is_sensitive_path
from plaidnox_sast.redaction import redact

from .diffing import Diff

ReviewDepth = Literal["FAST", "STANDARD", "DEEP"]


@dataclass(frozen=True, slots=True)
class ChangeRelevance:
    runtime_changed: bool
    security_control_changed: bool
    config_changed: bool
    sensitive_material_changed: bool
    dependency_or_build_changed: bool
    test_only: bool
    docs_only: bool
    generated_only: bool
    changed_files: tuple[str, ...]
    changed_symbols: tuple[str, ...]
    minimum_review_depth: ReviewDepth


_DOCS_EXTENSIONS = {".md", ".rst", ".txt", ".adoc"}
_DOCS_NAMES = {"readme", "changelog", "license", "notice", "contributing", "code_of_conduct"}
_GENERATED_MARKERS = ("dist/", "build/", "vendor/", "__generated__/", ".generated.")
_GENERATED_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock", "go.sum"}
_TEST_MARKERS = ("/test/", "/tests/", "/__tests__/", "/spec/")
_TEST_NAME_MARKERS = ("_test.", ".test.", "_spec.", ".spec.", "test_")
_CONFIG_EXTENSIONS = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env"}
_CONFIG_NAMES = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env"}
_DEPENDENCY_NAMES = {
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
    "go.mod",
    "go.sum",
    "gemfile",
    "gemfile.lock",
    "pom.xml",
    "build.gradle",
    "cargo.toml",
    "cargo.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
}
_SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".rs",
    ".kt",
    ".kts",
    ".swift",
    ".scala",
}
_SECURITY_PATH_KEYWORDS = (
    "auth",
    "authn",
    "authz",
    "session",
    "jwt",
    "token",
    "middleware",
    "permission",
    "acl",
    "rbac",
    "csrf",
    "cors",
    "crypto",
    "sign",
    "password",
    "login",
    "oauth",
    "saml",
    "credential",
    "identity",
    "security",
)
_SECURITY_CONTENT_PATTERNS = (
    re.compile(r"\bjwt\.decode\b", re.IGNORECASE),
    re.compile(r"\.verify\s*\(", re.IGNORECASE),
    re.compile(r"\bverify_token\b", re.IGNORECASE),
    re.compile(r"\brequire[_a-z]*auth\b", re.IGNORECASE),
    re.compile(r"\bis_?admin\b", re.IGNORECASE),
    re.compile(r"\bbcrypt\b", re.IGNORECASE),
    re.compile(r"\bcsrf\b", re.IGNORECASE),
)


def _split_ext(name: str) -> tuple[str, str]:
    if "." in name:
        stem, ext = name.rsplit(".", 1)
        return stem, f".{ext}"
    return name, ""


def _tags_for_path(path: str) -> set[str]:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    stem, ext = _split_ext(name)
    tags: set[str] = set()
    is_dependency = name in _DEPENDENCY_NAMES
    if is_dependency:
        tags.add("dependency")
    if not is_dependency and (ext in _DOCS_EXTENSIONS or stem in _DOCS_NAMES or name in _DOCS_NAMES):
        tags.add("docs")
    if any(marker in lowered for marker in _GENERATED_MARKERS) or name in _GENERATED_NAMES:
        tags.add("generated")
    if any(marker in lowered for marker in _TEST_MARKERS) or any(marker in name for marker in _TEST_NAME_MARKERS):
        tags.add("test")
    if not is_dependency and (ext in _CONFIG_EXTENSIONS or name in _CONFIG_NAMES):
        tags.add("config")
    if ext in _SOURCE_EXTENSIONS:
        tags.add("source")
    if any(keyword in lowered for keyword in _SECURITY_PATH_KEYWORDS):
        tags.add("security_path")
    return tags


def classify(diff: Diff, changed_symbols: Sequence[str] = ()) -> ChangeRelevance:
    if not diff.files:
        return ChangeRelevance(
            runtime_changed=False,
            security_control_changed=False,
            config_changed=False,
            sensitive_material_changed=False,
            dependency_or_build_changed=False,
            test_only=False,
            docs_only=False,
            generated_only=False,
            changed_files=(),
            changed_symbols=tuple(changed_symbols),
            minimum_review_depth="FAST",
        )

    file_tags = {file.path: _tags_for_path(file.path) for file in diff.files}
    docs_only = all("docs" in tags for tags in file_tags.values())
    generated_only = all("generated" in tags for tags in file_tags.values())
    test_only = all("test" in tags for tags in file_tags.values())
    config_changed = any("config" in tags for tags in file_tags.values())
    dependency_or_build_changed = any("dependency" in tags for tags in file_tags.values())
    runtime_changed = any("source" in tags and "test" not in tags for tags in file_tags.values())

    security_path_hit = any("security_path" in tags for tags in file_tags.values())
    security_content_hit = any(
        pattern.search(line)
        for file in diff.files
        for hunk in file.hunks
        for line in (*hunk.added_lines, *hunk.removed_lines)
        for pattern in _SECURITY_CONTENT_PATTERNS
    )
    security_control_changed = security_path_hit or security_content_hit

    sensitive_path_hit = any(_is_sensitive_path(Path(file.path)) for file in diff.files)
    sensitive_content_hit = any(
        redact(line) != line for file in diff.files for hunk in file.hunks for line in hunk.added_lines
    )
    sensitive_material_changed = sensitive_path_hit or sensitive_content_hit

    depth: ReviewDepth
    if security_control_changed or sensitive_material_changed:
        depth = "DEEP"
    elif docs_only or generated_only or test_only and not (config_changed or dependency_or_build_changed or runtime_changed):
        depth = "FAST"
    elif config_changed or dependency_or_build_changed or runtime_changed:
        depth = "STANDARD"
    else:
        depth = "FAST"

    return ChangeRelevance(
        runtime_changed=runtime_changed,
        security_control_changed=security_control_changed,
        config_changed=config_changed,
        sensitive_material_changed=sensitive_material_changed,
        dependency_or_build_changed=dependency_or_build_changed,
        test_only=test_only,
        docs_only=docs_only,
        generated_only=generated_only,
        changed_files=tuple(sorted(file_tags)),
        changed_symbols=tuple(changed_symbols),
        minimum_review_depth=depth,
    )
