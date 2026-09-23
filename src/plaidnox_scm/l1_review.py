"""Changed-file-first Layer-1 AI review for PR/MR deltas."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from plaidnox_sast.assets import load_json as load_sast_json
from plaidnox_sast.graph import FileSecurityIR, build_file_security_ir
from plaidnox_sast.redaction import redact_payload

from .assets import load_json
from .change_relevance import ChangeRelevance
from .context_store import ApplicationContext
from .diffing import ChangedFile, Diff
from .prompts import render_operation
from .snapshots import materialize_revision, read_blob


class L1ReviewError(RuntimeError):
    """Raised when changed-file hypothesis discovery cannot be completed safely."""


class ResponsesClient(Protocol):
    class responses:  # type: ignore[valid-type]
        @staticmethod
        def create(**kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class ChangedLines:
    start: int
    end: int


@dataclass(frozen=True, slots=True)
class ExpansionRequest:
    kind: str
    target: str
    reason: str


@dataclass(frozen=True, slots=True)
class L1Candidate:
    candidate_id: str
    changed_path: str
    changed_symbol: str
    changed_lines: ChangedLines
    behavior_before: str
    behavior_after: str
    security_role: str
    suspected_broken_invariant: str
    provisional_attacker_capability: str
    context_facts_used: tuple[str, ...]
    context_gaps: tuple[str, ...]
    requested_expansion: tuple[ExpansionRequest, ...]


@dataclass(frozen=True, slots=True)
class L1ReviewBatch:
    candidates: tuple[L1Candidate, ...]
    reviewed_paths: tuple[str, ...]
    coverage_complete: bool
    coverage_gaps: tuple[str, ...]
    model_calls: int


class ChangedFileReviewer(Protocol):
    def review(
        self,
        repo_path: Path,
        diff: Diff,
        relevance: ChangeRelevance,
        application_context: ApplicationContext,
    ) -> L1ReviewBatch: ...


class LiteLLMChangedFileReviewer:
    """One structured LiteLLM review call per changed runtime/configuration file."""

    def __init__(self, client: ResponsesClient) -> None:
        self._client = client

    def review(
        self,
        repo_path: Path,
        diff: Diff,
        relevance: ChangeRelevance,
        application_context: ApplicationContext,
    ) -> L1ReviewBatch:
        runtime = load_json("runtime/review.json")
        schema = load_json("schemas/changed_file_review.json")
        model_tier = str(runtime["l1_model_tier"])
        model = str(load_sast_json("runtime/models.json")["agent_model_by_tier"][model_tier])
        candidates: list[L1Candidate] = []
        reviewed_paths: list[str] = []
        coverage_gaps: list[str] = []
        coverage_complete = True
        maximum_bytes = int(runtime["maximum_file_bytes"])

        with materialize_revision(repo_path, diff.head_ref) as head_root:
            for changed_file in diff.files:
                reviewed_paths.append(changed_file.path)
                payload = _review_payload(
                    repo_path,
                    diff,
                    changed_file,
                    relevance,
                    application_context,
                    build_file_security_ir(head_root, changed_file.path, maximum_bytes),
                    maximum_bytes,
                    int(runtime["maximum_application_context_characters"]),
                )
                system_prompt, user_prompt = render_operation("changed_file_review", redact_payload(payload))
                response = self._client.responses.create(
                    model=model,
                    reasoning={"effort": str(runtime["l1_reasoning_effort"])},
                    input=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    text={
                        "verbosity": "low",
                        "format": {
                            "type": "json_schema",
                            "name": "plaidnox_scm_changed_file_review",
                            "strict": True,
                            "schema": schema,
                        },
                    },
                    max_output_tokens=int(runtime["l1_max_output_tokens"]),
                )
                if getattr(response, "status", "completed") != "completed":
                    raise L1ReviewError(f"L1 review was incomplete for {changed_file.path}")
                result = _parse_response(response, changed_file)
                candidates.extend(result[0])
                coverage_complete = coverage_complete and result[1]
                coverage_gaps.extend(result[2])

        return L1ReviewBatch(
            candidates=tuple(candidates),
            reviewed_paths=tuple(reviewed_paths),
            coverage_complete=coverage_complete,
            coverage_gaps=tuple(coverage_gaps),
            model_calls=len(reviewed_paths),
        )


def _review_payload(
    repo_path: Path,
    diff: Diff,
    changed_file: ChangedFile,
    relevance: ChangeRelevance,
    application_context: ApplicationContext,
    security_ir: FileSecurityIR | None,
    maximum_bytes: int,
    maximum_context_characters: int,
) -> dict[str, Any]:
    context_value = asdict(application_context)
    context_value["computed_at"] = application_context.computed_at.isoformat()
    context_json = json.dumps(context_value, ensure_ascii=False, default=str)
    if len(context_json) > maximum_context_characters:
        context_value = {
            "codebase_id": application_context.codebase_id,
            "baseline_revision": application_context.baseline_revision,
            "application_type": application_context.application_type,
            "entry_points": application_context.entry_points,
            "components": application_context.components,
            "security_controls": application_context.security_controls,
            "routes": application_context.routes,
            "sensitive_effects": application_context.sensitive_effects,
            "confidence": application_context.confidence,
            "context_version": application_context.context_version,
            "truncated": True,
        }
    old_path = changed_file.old_path or changed_file.path
    return {
        "base_revision": application_context.baseline_revision,
        "head_revision": diff.head_ref,
        "change_relevance": asdict(relevance),
        "application_context": context_value,
        "changed_file": {
            "path": changed_file.path,
            "old_path": changed_file.old_path,
            "status": changed_file.status,
            "hunks": [asdict(hunk) for hunk in changed_file.hunks],
            "baseline_source": read_blob(repo_path, diff.base_ref, old_path, maximum_bytes),
            "head_source": read_blob(repo_path, diff.head_ref, changed_file.path, maximum_bytes),
            "local_security_ir": _serialize_ir(security_ir),
        },
    }


def _serialize_ir(value: FileSecurityIR | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "path": value.path,
        "language": value.language,
        "content_hash": value.content_hash,
        "symbols": [asdict(item) for item in value.symbols],
        "calls": [asdict(item) for item in value.calls],
        "imports": list(value.imports),
    }


def _response_text(response: Any) -> str:
    """Return the model's structured answer text.

    Some reasoning models occasionally place the final structured answer in a
    ``reasoning``-typed output item instead of a ``message``-typed one, which
    leaves the SDK's ``output_text`` convenience property empty even though a
    valid answer was produced. Fall back to scanning every output item's
    content blocks for text in that case.
    """
    text = getattr(response, "output_text", "")
    if text:
        return str(text)
    for item in getattr(response, "output", None) or []:
        for block in getattr(item, "content", None) or []:
            block_text = getattr(block, "text", None)
            if block_text:
                return str(block_text)
    return ""


def _parse_response(
    response: Any,
    changed_file: ChangedFile,
) -> tuple[list[L1Candidate], bool, list[str]]:
    try:
        payload = json.loads(_response_text(response))
        raw_candidates = list(payload["candidates"])
        coverage_complete = bool(payload["coverage_complete"])
        coverage_gaps = [str(item) for item in payload["coverage_gaps"]]
    except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise L1ReviewError(f"L1 response did not match the schema for {changed_file.path}") from exc

    candidates: list[L1Candidate] = []
    for item in raw_candidates:
        if str(item["changed_path"]) != changed_file.path:
            raise L1ReviewError("L1 candidate path was not the file under review")
        start = int(item["changed_lines"]["start"])
        end = int(item["changed_lines"]["end"])
        if end < start or not _intersects_changed_lines(changed_file, start, end):
            raise L1ReviewError("L1 candidate was not anchored to a changed line range")
        candidates.append(
            L1Candidate(
                candidate_id=str(item["candidate_id"]),
                changed_path=changed_file.path,
                changed_symbol=str(item["changed_symbol"]),
                changed_lines=ChangedLines(start, end),
                behavior_before=str(item["behavior_before"]),
                behavior_after=str(item["behavior_after"]),
                security_role=str(item["security_role"]),
                suspected_broken_invariant=str(item["suspected_broken_invariant"]),
                provisional_attacker_capability=str(item["provisional_attacker_capability"]),
                context_facts_used=tuple(str(value) for value in item["context_facts_used"]),
                context_gaps=tuple(str(value) for value in item["context_gaps"]),
                requested_expansion=tuple(
                    ExpansionRequest(str(value["kind"]), str(value["target"]), str(value["reason"]))
                    for value in item["requested_expansion"]
                ),
            )
        )
    return candidates, coverage_complete, coverage_gaps


def _intersects_changed_lines(changed_file: ChangedFile, start: int, end: int) -> bool:
    for hunk in changed_file.hunks:
        ranges = ((hunk.new_start, hunk.new_start + max(hunk.new_lines, 1) - 1),)
        if changed_file.status == "deleted":
            ranges = ((hunk.old_start, hunk.old_start + max(hunk.old_lines, 1) - 1),)
        if any(start <= range_end and end >= range_start for range_start, range_end in ranges):
            return True
    return False
