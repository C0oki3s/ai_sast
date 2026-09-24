"""Discovery correctness/efficiency layer for PlaidNox Deep Hunt.

This module keeps the stable Deep Hunt verifier in :mod:`plaidnox_sast.ai` and
overrides only candidate discovery. The discovery identity is structural and
semantic: source content + Security IR + security obligations, never transient
planner/query identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from .ai import (
    AIRepositoryContext,
    AIResponseError,
    HuntPlan,
    PlaidNoxDeepHuntAgent,
    _candidate_from_ai_item,
    _enclosing_symbol,
    _is_generated_path,
    _related_ir,
    _resolve_context_request,
    _source_window,
    _source_segments,
)
from .assets import load_json, load_text
from .checkpoint import candidate_from_dict, candidate_to_dict, unit_key
from .coverage import obligation_identity, reconcile_obligations
from .errors import AIStageError
from .fingerprint import CandidateIndex
from .graph import (
    RipgrepDiscovery,
    RipgrepQueryError,
    SearchHit,
    StructuralGraph,
    source_file_is_admitted,
    source_files,
)
from .models import Candidate
from .redaction import redact


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _coverage_observations(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    obligations = {
        str(item.get("obligation_id", "")): dict(item)
        for item in state.get("obligations", [])
        if isinstance(item, Mapping) and item.get("obligation_id")
    }
    dispositions = {
        str(item.get("obligation_id", "")): dict(item)
        for item in state.get("dispositions", [])
        if isinstance(item, Mapping) and item.get("obligation_id")
    }
    region_id = str(state.get("region_id", ""))
    return [
        {
            "region_id": region_id,
            "obligation": obligation,
            "status": str(dispositions.get(obligation_id, {}).get("status", "UNRESOLVED")),
        }
        for obligation_id, obligation in obligations.items()
    ]


@dataclass(slots=True)
class DiscoveryRegion:
    """One structural source region reviewed at most once per semantic obligation set."""

    path: str
    start_line: int
    end_line: int
    content: str
    anchor_type: str
    anchor_id: str
    content_hash: str
    security_ir_hash: str
    task_ids: set[str] = field(default_factory=set)
    query_ids: set[str] = field(default_factory=set)
    coverage_refs: set[str] = field(default_factory=set)
    obligations: set[str] = field(default_factory=set)
    obligation_specs: dict[str, "DiscoveryObligation"] = field(default_factory=dict)
    vulnerability_themes: set[str] = field(default_factory=set)
    security_ir_slice: dict[str, Any] = field(default_factory=dict)

    @property
    def region_id(self) -> str:
        return _stable_hash(
            {
                "path": self.path,
                "anchor_type": self.anchor_type,
                "anchor_id": self.anchor_id,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "content_hash": self.content_hash,
                "security_ir_hash": self.security_ir_hash,
            }
        )[:24]

    def checkpoint_key(self, prompt_version: str) -> str:
        """Stable cache identity: source/IR + what security work is being asked."""

        return unit_key(
            "discovery-v3",
            {
                "path": self.path,
                "anchor_type": self.anchor_type,
                "anchor_id": self.anchor_id,
                "content_hash": self.content_hash,
                "security_ir_hash": self.security_ir_hash,
                "obligations": [
                    self.obligation_specs[key].to_dict()
                    for key in sorted(self.obligation_specs)
                ],
                "vulnerability_themes": sorted(self.vulnerability_themes),
                "prompt_version": prompt_version,
            },
        )

    def to_segment(self) -> dict[str, Any]:
        return {
            "region_id": self.region_id,
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "content": self.content,
            "anchor_type": self.anchor_type,
            "anchor_id": self.anchor_id,
            "content_hash": self.content_hash,
            "security_ir_hash": self.security_ir_hash,
            "query_ids": sorted(self.query_ids),
            "task_ids": sorted(self.task_ids),
            "coverage_refs": sorted(self.coverage_refs),
            "obligations": sorted(self.obligations),
            "obligation_ids": sorted(self.obligation_specs),
            "vulnerability_themes": sorted(self.vulnerability_themes),
            "security_ir_slice": self.security_ir_slice,
        }


class ObligationStatus(StrEnum):
    NO_ISSUE = "NO_ISSUE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    CANDIDATE_FOUND = "CANDIDATE_FOUND"
    NEEDS_CONTEXT = "NEEDS_CONTEXT"
    UNRESOLVED = "UNRESOLVED"


_TERMINAL_OBLIGATION_STATUSES = {
    ObligationStatus.NO_ISSUE,
    ObligationStatus.NOT_APPLICABLE,
    ObligationStatus.CANDIDATE_FOUND,
    ObligationStatus.UNRESOLVED,
}


@dataclass(frozen=True, slots=True)
class DiscoveryObligation:
    obligation_id: str
    obligation_type: str
    question: str
    scope: str = "LOCAL"
    canonical_id: str = ""
    importance: str = ""

    def __post_init__(self) -> None:
        if not self.canonical_id or not self.importance:
            canonical_id, importance = obligation_identity(
                self.obligation_type, self.question
            )
            if not self.canonical_id:
                object.__setattr__(self, "canonical_id", canonical_id)
            if not self.importance:
                object.__setattr__(self, "importance", importance)

    def to_dict(self) -> dict[str, str]:
        return {
            "obligation_id": self.obligation_id,
            "type": self.obligation_type,
            "scope": self.scope,
            "canonical_id": self.canonical_id,
            "importance": self.importance,
            "question": self.question,
        }


@dataclass(slots=True)
class DiscoveryCoverageState:
    region_id: str
    obligations: dict[str, DiscoveryObligation]
    dispositions: dict[str, dict[str, Any]] = field(default_factory=dict)
    requested_context: set[str] = field(default_factory=set)
    resolved_context: set[str] = field(default_factory=set)
    candidate_ids: set[str] = field(default_factory=set)
    needs_context_ids: set[str] = field(default_factory=set)
    contract_issues: list[str] = field(default_factory=list)
    grounding_rejections: int = 0

    @property
    def processing_complete(self) -> bool:
        return bool(self.obligations) and all(
            ObligationStatus(str(self.dispositions.get(obligation_id, {}).get("status", "NEEDS_CONTEXT")))
            in _TERMINAL_OBLIGATION_STATUSES
            for obligation_id in self.obligations
        )

    @property
    def coverage_complete(self) -> bool:
        return self.processing_complete and all(
            ObligationStatus(str(self.dispositions.get(obligation_id, {}).get("status", "NEEDS_CONTEXT")))
            is not ObligationStatus.UNRESOLVED
            for obligation_id in self.obligations
        )

    @property
    def complete(self) -> bool:
        """Compatibility alias for operational completion, not security coverage."""
        return self.processing_complete

    def unresolved_ids(self) -> list[str]:
        return [
            obligation_id
            for obligation_id in self.obligations
            if ObligationStatus(str(self.dispositions.get(obligation_id, {}).get("status", "NEEDS_CONTEXT")))
            == ObligationStatus.NEEDS_CONTEXT
        ]

    def apply(
        self,
        results: list[dict[str, Any]],
        candidate_ids: set[str],
        rejected_candidate_ids: set[str] | None = None,
    ) -> None:
        rejected_candidate_ids = rejected_candidate_ids or set()
        expected = set(self.unresolved_ids()) if self.dispositions else set(self.obligations)
        results_by_id: dict[str, list[dict[str, Any]]] = {}
        for result in results:
            results_by_id.setdefault(str(result.get("obligation_id", "")), []).append(result)
        unknown = sorted(set(results_by_id) - set(self.obligations))
        if unknown:
            self.contract_issues.append("response included unknown obligation identifiers")
        for obligation_id in expected:
            matching = results_by_id.get(obligation_id, [])
            if len(matching) != 1:
                issue = "response omitted an obligation disposition" if not matching else "response duplicated an obligation disposition"
                self.contract_issues.append(issue)
                self.mark_unresolved([obligation_id], issue)
                continue
            result = matching[0]
            try:
                status = ObligationStatus(str(result["status"]))
                linked_candidates = {str(item) for item in result.get("candidate_ids", [])}
                requests = [dict(item) for item in result.get("context_requests", [])]
            except (KeyError, TypeError, ValueError):
                self.contract_issues.append("response contained a malformed obligation disposition")
                self.mark_unresolved([obligation_id], "Malformed obligation disposition; manual or later re-review required.")
                continue
            if status is ObligationStatus.CANDIDATE_FOUND:
                if not linked_candidates or not linked_candidates <= candidate_ids:
                    rejected_only = bool(linked_candidates) and linked_candidates <= rejected_candidate_ids
                    if rejected_only:
                        self.grounding_rejections += 1
                    else:
                        self.contract_issues.append("candidate disposition did not link to a grounded candidate")
                    self.mark_unresolved(
                        [obligation_id],
                        "Candidate evidence could not be grounded to an accepted source location.",
                    )
                    continue
            elif linked_candidates:
                self.contract_issues.append("non-candidate disposition linked candidate identifiers")
                self.mark_unresolved([obligation_id], "Invalid candidate link in obligation disposition.")
                continue
            if status is ObligationStatus.NEEDS_CONTEXT and not requests:
                self.contract_issues.append("NEEDS_CONTEXT disposition omitted a typed context request")
                self.mark_unresolved([obligation_id], "No resolvable context request was supplied.")
                continue
            if status is not ObligationStatus.NEEDS_CONTEXT and requests:
                self.contract_issues.append("terminal obligation disposition included context requests")
                self.mark_unresolved([obligation_id], "Terminal disposition contained an invalid context request.")
                continue
            self.dispositions[obligation_id] = dict(result)
            self.candidate_ids.update(linked_candidates)
            self.needs_context_ids.discard(obligation_id)
            if status is ObligationStatus.NEEDS_CONTEXT:
                self.needs_context_ids.add(obligation_id)

    def mark_unresolved(self, obligation_ids: list[str], reason: str) -> None:
        for obligation_id in obligation_ids:
            prior = dict(self.dispositions.get(obligation_id, {}))
            prior.update(
                {
                    "obligation_id": obligation_id,
                    "status": ObligationStatus.UNRESOLVED.value,
                    "candidate_ids": [],
                    "context_requests": [],
                    "reason": reason,
                }
            )
            self.dispositions[obligation_id] = prior

    def to_dict(self) -> dict[str, Any]:
        return {
            "region_id": self.region_id,
            "obligations": [item.to_dict() for item in self.obligations.values()],
            "dispositions": list(self.dispositions.values()),
            "requested_context": sorted(self.requested_context),
            "resolved_context": sorted(self.resolved_context),
            "candidate_ids": sorted(self.candidate_ids),
            "needs_context_ids": sorted(self.needs_context_ids),
            "contract_issues": list(self.contract_issues),
            "grounding_rejections": self.grounding_rejections,
            "processing_complete": self.processing_complete,
            "coverage_complete": self.coverage_complete,
            "complete": self.complete,
        }


@dataclass(slots=True)
class _HitAggregate:
    hit: SearchHit
    query_ids: set[str] = field(default_factory=set)
    task_ids: set[str] = field(default_factory=set)
    coverage_refs: set[str] = field(default_factory=set)


def _region_from_range(
    root: Path,
    graph: StructuralGraph | None,
    path: str,
    start_line: int,
    end_line: int,
    *,
    task_ids: set[str] | None = None,
    query_ids: set[str] | None = None,
    coverage_refs: set[str] | None = None,
    anchor: Any | None = None,
) -> DiscoveryRegion | None:
    target = root / path
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    start = max(1, start_line)
    end = min(len(lines), max(start, end_line))
    content = redact("\n".join(lines[start - 1 : end]))
    resolved_anchor = anchor or _enclosing_symbol(graph, path, start)
    if resolved_anchor is None:
        anchor_type = "line_range"
        anchor_id = f"{path}:{start}-{end}"
        related_symbol = ""
    else:
        anchor_type = "route" if str(getattr(resolved_anchor, "kind", "")) == "route" else "symbol"
        anchor_id = str(
            getattr(resolved_anchor, "qualified_name", "")
            or getattr(resolved_anchor, "name", "")
            or f"{path}:{start}-{end}"
        )
        related_symbol = str(getattr(resolved_anchor, "name", ""))
    security_ir_slice = _related_ir(graph, path, related_symbol)
    return DiscoveryRegion(
        path=path,
        start_line=start,
        end_line=end,
        content=content,
        anchor_type=anchor_type,
        anchor_id=anchor_id,
        content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        security_ir_hash=_stable_hash(security_ir_slice),
        task_ids=set(task_ids or ()),
        query_ids=set(query_ids or ()),
        coverage_refs=set(coverage_refs or ()),
        security_ir_slice=security_ir_slice,
    )


def _enrich_region_requirements(region: DiscoveryRegion, plan: HuntPlan) -> None:
    region.obligations.clear()
    region.obligation_specs.clear()
    region.vulnerability_themes.clear()
    selected = _tasks_relevant_to_region(region, plan)
    aggregate: dict[str, dict[str, set[str]]] = {}
    objectives: set[str] = set()
    for task in selected:
        task_data = _region_task_payload(task, region)
        region.obligations.update(str(item) for item in task_data["coverage_obligations"])
        region.vulnerability_themes.update(str(item) for item in task_data["vulnerability_themes"])
        grouped_requirements = {
            "security_invariant": {
                "business_invariants": task_data["business_invariants"],
                "vulnerability_themes": task_data["vulnerability_themes"],
            },
            "coverage": {
                "coverage_obligations": task_data["coverage_obligations"],
                "entry_points": task_data["entry_points"],
                "focus_paths": task_data["focus_paths"],
                "inventory_refs": task_data["inventory_refs"],
                "evidence_requirements": task_data["evidence_requirements"],
                "falsification_requirements": task_data["falsification_requirements"],
            },
            "sensitive_effect": {
                "sensitive_effect_refs": task_data["sensitive_effect_refs"],
                "authentication_path_refs": task_data["authentication_path_refs"],
            },
        }
        for obligation_type, fields in grouped_requirements.items():
            grouped = aggregate.setdefault(obligation_type, {})
            for name, values in fields.items():
                grouped.setdefault(name, set()).update(str(item).strip() for item in values if str(item).strip())
        if task_data["objective"].strip():
            objectives.add(task_data["objective"].strip())

    canonical_fields = load_json("runtime/coverage.json")["canonical_fields_by_type"]
    for obligation_type, fields in aggregate.items():
        identity_fields = canonical_fields.get(obligation_type, [])
        # Keep independently meaningful obligations separate. If one region has
        # two invariants and a sibling has only one, global reconciliation can
        # now match the shared invariant without treating the pair as different
        # work. Broad themes remain discovery guidance, not coverage identities.
        for field_name in identity_fields:
            for value in sorted(fields.get(field_name, set())):
                requirements = {field_name: [value]}
                question = json.dumps(
                    requirements, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                canonical_id, importance = obligation_identity(
                    obligation_type, question, region_id=region.region_id
                )
                obligation_id = f"obl-{canonical_id[:20]}"
                region.obligation_specs[obligation_id] = DiscoveryObligation(
                    obligation_id,
                    obligation_type,
                    question,
                    canonical_id=canonical_id,
                    importance=importance,
                )
    if not region.obligation_specs and objectives:
        requirements = {"objectives": sorted(objectives)}
        question = json.dumps(requirements, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        obligation_id = f"obl-{_stable_hash({'type': 'task_objective', 'requirements': requirements})[:20]}"
        canonical_id, importance = obligation_identity(
            "task_objective", question, region_id=region.region_id
        )
        region.obligation_specs[obligation_id] = DiscoveryObligation(
            obligation_id,
            "task_objective",
            question,
            canonical_id=canonical_id,
            importance=importance,
        )
    if not region.obligation_specs:
        local_review = load_text(
            "prompts/operations/vulnerability_discovery/local_obligations.md"
        ).strip()
        requirements = {
            "scope": region.anchor_type,
            "anchor": region.anchor_id,
            "path": region.path,
            "review": local_review,
        }
        question = json.dumps(requirements, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        obligation_id = f"obl-{_stable_hash({'type': 'local_review', 'requirements': requirements})[:20]}"
        region.obligations.add(local_review)
        canonical_id, importance = obligation_identity(
            "local_review", question, region_id=region.region_id
        )
        region.obligation_specs[obligation_id] = DiscoveryObligation(
            obligation_id,
            "local_review",
            question,
            "LOCAL",
            canonical_id,
            importance,
        )


def _tasks_relevant_to_region(region: DiscoveryRegion, plan: HuntPlan) -> list[Any]:
    selected = [task for task in plan.tasks if task.task_id in region.task_ids]
    if not selected:
        selected = list(plan.tasks)

    route_matches: list[Any] = []
    if region.anchor_type == "route":
        route_name = region.anchor_id.removeprefix("route:").strip().casefold()
        route_matches = [
            task
            for task in selected
            if route_name in {str(entry).strip().casefold() for entry in task.entry_points}
        ]
    elif region.anchor_type == "line_range":
        region_routes = {
            str(symbol.get("qualified_name") or symbol.get("name") or "")
            .removeprefix("route:")
            .casefold()
            for symbol in region.security_ir_slice.get("symbols", [])
            if symbol.get("kind") == "route"
            and int(symbol.get("line", 0)) <= region.end_line
            and int(symbol.get("end_line", 0)) >= region.start_line
        }
        route_matches = [
            task
            for task in selected
            if region_routes
            & {str(entry).strip().casefold() for entry in task.entry_points}
        ]
    if route_matches:
        return route_matches
    if region.anchor_type == "route" or (
        region.anchor_type == "line_range" and region_routes
    ):
        # A route-anchored region must not inherit every task that happens to
        # mention the same controller file. Global application obligations are
        # handled by planning/context stages, not copied into each route review.
        return []

    focus_matches = [
        task
        for task in selected
        if not task.focus_paths
        or any(_focus_reference_overlaps_region(str(focus), region) for focus in task.focus_paths)
    ]
    return focus_matches


def _focus_reference_overlaps_region(reference: str, region: DiscoveryRegion) -> bool:
    """Match path-only or path:line[-line] hunt-plan references structurally."""
    match = re.fullmatch(r"(?P<path>.*?)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?", reference.strip())
    if not match:
        return False
    path = match.group("path").replace("\\", "/").removeprefix("./").strip("/")
    region_path = region.path.replace("\\", "/").removeprefix("./").strip("/")
    if region_path != path and not region_path.startswith(path.rstrip("/") + "/"):
        return False
    if path != region_path or match.group("start") is None:
        return True
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    return start <= region.end_line and region.start_line <= end


def _region_task_payload(task: Any, region: DiscoveryRegion) -> dict[str, Any]:
    """Project a plan task onto the local region before it reaches discovery."""
    value = task.to_dict()
    value["scope"] = "LOCAL"
    value["region_anchor"] = {
        "type": region.anchor_type,
        "id": region.anchor_id,
        "path": region.path,
        "start_line": region.start_line,
        "end_line": region.end_line,
    }
    if region.anchor_type != "route":
        return value

    route = region.anchor_id.removeprefix("route:").strip()
    path = region.path
    value["focus_paths"] = [path]
    value["entry_points"] = [route]
    route_terms = {route.casefold(), path.casefold()}
    for field_name in (
        "coverage_obligations",
        "evidence_requirements",
        "falsification_requirements",
        "inventory_refs",
        "sensitive_effect_refs",
        "authentication_path_refs",
    ):
        values = [str(item) for item in value.get(field_name, [])]
        matches = [
            item
            for item in values
            if any(term and term in item.casefold() for term in route_terms)
        ]
        value[field_name] = matches or (values[:1] if len(values) == 1 else [])
    return value


def _can_merge_regions(first: DiscoveryRegion, second: DiscoveryRegion, ratio: float, gap: int) -> bool:
    if first.path != second.path:
        return False
    same_anchor = first.anchor_type == second.anchor_type and first.anchor_id == second.anchor_id
    overlap = min(first.end_line, second.end_line) - max(first.start_line, second.start_line) + 1
    second_length = max(1, second.end_line - second.start_line + 1)
    overlap_ratio = max(0, overlap) / second_length
    if same_anchor:
        return overlap_ratio >= ratio or second.start_line - first.end_line <= gap
    # Keep distinct structural anchors separate even if their context windows overlap.
    return first.anchor_type == "line_range" and second.anchor_type == "line_range" and overlap_ratio >= ratio


def _merge_discovery_regions(
    root: Path,
    regions: list[DiscoveryRegion],
    graph: StructuralGraph | None,
    runtime_agent: Mapping[str, Any],
) -> tuple[list[DiscoveryRegion], int]:
    """Merge only semantically compatible windows and size the actual merged span."""

    ratio = float(runtime_agent["region_overlap_ratio"])
    gap = int(runtime_agent["region_max_gap_lines"])
    limit = int(runtime_agent["region_max_characters"])
    by_path: dict[str, list[DiscoveryRegion]] = {}
    for region in regions:
        by_path.setdefault(region.path, []).append(region)

    merged_all: list[DiscoveryRegion] = []
    merged_windows = 0
    for path, items in by_path.items():
        items.sort(key=lambda item: (item.start_line, item.end_line, item.anchor_id))
        current: DiscoveryRegion | None = None
        for item in items:
            if current is not None and _can_merge_regions(current, item, ratio, gap):
                merged_start = min(current.start_line, item.start_line)
                merged_end = max(current.end_line, item.end_line)
                candidate = _region_from_range(
                    root,
                    graph,
                    path,
                    merged_start,
                    merged_end,
                    task_ids=current.task_ids | item.task_ids,
                    query_ids=current.query_ids | item.query_ids,
                    coverage_refs=current.coverage_refs | item.coverage_refs,
                    anchor=(
                        _enclosing_symbol(graph, path, merged_start)
                        if current.anchor_id != item.anchor_id
                        else _enclosing_symbol(graph, path, current.start_line)
                    ),
                )
                if candidate is not None and len(candidate.content) <= limit:
                    candidate.obligations = current.obligations | item.obligations
                    candidate.obligation_specs = {
                        **current.obligation_specs,
                        **item.obligation_specs,
                    }
                    candidate.vulnerability_themes = (
                        current.vulnerability_themes | item.vulnerability_themes
                    )
                    # Preserve the stable anchor when both windows belong to it.
                    if current.anchor_id == item.anchor_id and current.anchor_type == item.anchor_type:
                        candidate.anchor_id = current.anchor_id
                        candidate.anchor_type = current.anchor_type
                    current = candidate
                    merged_windows += 1
                    continue
                merged_all.append(current)
            elif current is not None:
                merged_all.append(current)
            current = item
        if current is not None:
            merged_all.append(current)
    return merged_all, merged_windows


def _subtract_covered_ranges(
    start_line: int,
    end_line: int,
    covered: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Return inclusive portions of ``start..end`` not covered by existing regions."""

    remaining = [(start_line, end_line)]
    for covered_start, covered_end in sorted(covered):
        next_remaining: list[tuple[int, int]] = []
        for start, end in remaining:
            if covered_end < start or covered_start > end:
                next_remaining.append((start, end))
                continue
            if covered_start > start:
                next_remaining.append((start, covered_start - 1))
            if covered_end < end:
                next_remaining.append((covered_end + 1, end))
        remaining = next_remaining
        if not remaining:
            break
    return remaining


def _focus_paths_for_missing_tasks(plan: HuntPlan, eligible: set[str], missing: set[str]) -> dict[str, set[str]]:
    import fnmatch

    focus_paths: dict[str, set[str]] = {}
    for task in plan.tasks:
        if task.task_id not in missing:
            continue
        for focus in task.focus_paths:
            for path in eligible:
                if (
                    path == focus
                    or path.startswith(focus.rstrip("/") + "/")
                    or fnmatch.fnmatch(path, focus)
                ):
                    focus_paths.setdefault(path, set()).add(task.task_id)
    return focus_paths


def _canonical_queries(queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    canonical: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for query in queries:
        identity = (
            tuple(sorted({str(item).strip().lower() for item in query["search_terms"] if str(item).strip()})),
            tuple(sorted({str(item) for item in query.get("include_globs", [])})),
        )
        merged = canonical.setdefault(
            identity,
            {
                "query_id": str(query["query_id"]),
                "search_terms": list(query["search_terms"]),
                "include_globs": list(query.get("include_globs", [])),
                "query_ids": set(),
                "task_ids": set(),
                "coverage_refs": set(),
            },
        )
        merged["query_ids"].add(str(query["query_id"]))
        merged["task_ids"].update(str(item) for item in query.get("task_ids", []))
        merged["coverage_refs"].update(str(item) for item in query.get("coverage_refs", []))
    return list(canonical.values())


def _search_discovery_regions(
    root: Path,
    queries: list[dict[str, Any]],
    plan: HuntPlan,
    graph: StructuralGraph | None,
    exclude: list[str] | None,
    max_file_bytes: int | None,
    include_paths: set[str] | None = None,
    error_sink: Callable[[RipgrepQueryError], None] | None = None,
    stats: dict[str, int] | None = None,
) -> list[DiscoveryRegion]:
    eligible = {
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
        if not _is_sensitive_path(path)
        and not _is_generated_path(path)
        and (include_paths is None or path.relative_to(root).as_posix() in include_paths)
    }
    rg = RipgrepDiscovery(root, exclude=exclude or [], max_file_bytes=max_file_bytes)
    canonical = _canonical_queries(queries)
    if stats is not None:
        stats["queries_raw"] = len(queries)
        stats["queries_unique"] = len(canonical)

    hits_by_location: dict[tuple[str, int], _HitAggregate] = {}
    raw_hits = 0
    tasks_with_hits: set[str] = set()
    for query in canonical:
        try:
            hits = rg.search_literals(
                str(query["query_id"]),
                [str(item) for item in query["search_terms"]],
                include_globs=[str(item) for item in query["include_globs"]],
                exclude_globs=exclude or [],
            )
        except RipgrepQueryError as exc:
            if error_sink is not None:
                error_sink(exc)
            continue
        raw_hits += len(hits)
        for hit in hits:
            if hit.path not in eligible:
                continue
            key = (hit.path, hit.line)
            aggregate = hits_by_location.setdefault(key, _HitAggregate(hit))
            aggregate.query_ids.update(query["query_ids"])
            aggregate.task_ids.update(query["task_ids"])
            aggregate.coverage_refs.update(query["coverage_refs"])
            tasks_with_hits.update(query["task_ids"])

    if stats is not None:
        stats["rg_hits_raw"] = raw_hits
        stats["rg_hits_unique"] = len(hits_by_location)

    runtime = load_json("runtime/code_intelligence.json")
    runtime_agent = load_json("runtime/agent.json")
    before = int(runtime["context_lines_before"])
    after = int(runtime["context_lines_after"])
    regions_by_key: dict[tuple[str, int, int, str, str], DiscoveryRegion] = {}
    for aggregate in hits_by_location.values():
        hit = aggregate.hit
        target = root / hit.path
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        enclosing = _enclosing_symbol(graph, hit.path, hit.line)
        start_line = max(1, (enclosing.line if enclosing else hit.line) - before)
        structural_end = (
            enclosing.end_line
            if enclosing is not None and enclosing.end_line >= enclosing.line
            else hit.line
        )
        end_line = min(len(lines), structural_end + after)
        region = _region_from_range(
            root,
            graph,
            hit.path,
            start_line,
            end_line,
            task_ids=aggregate.task_ids,
            query_ids=aggregate.query_ids,
            coverage_refs=aggregate.coverage_refs,
            anchor=enclosing,
        )
        if region is None:
            continue
        key = (region.path, region.start_line, region.end_line, region.anchor_type, region.anchor_id)
        existing = regions_by_key.get(key)
        if existing is None:
            regions_by_key[key] = region
        else:
            existing.query_ids.update(region.query_ids)
            existing.task_ids.update(region.task_ids)
            existing.coverage_refs.update(region.coverage_refs)

    windows = list(regions_by_key.values())
    for region in windows:
        _enrich_region_requirements(region, plan)
    if stats is not None:
        stats["windows_raw"] = len(windows)

    regions, merged_windows = _merge_discovery_regions(root, windows, graph, runtime_agent)
    for region in regions:
        _enrich_region_requirements(region, plan)
    if stats is not None:
        stats["windows_merged"] = merged_windows
        stats["regions_after_merge"] = len(regions)
        stats["overlap_suppressed"] = max(0, len(windows) - len(regions))

    missing_task_ids = {task.task_id for task in plan.tasks} - tasks_with_hits
    focus_paths = _focus_paths_for_missing_tasks(plan, eligible, missing_task_ids)
    fallback_segments = _source_segments(
        root,
        int(runtime_agent["source_segment_characters"]),
        include_paths=set(focus_paths),
        exclude=exclude,
        max_file_bytes=max_file_bytes,
    )
    fallback_requested = len(fallback_segments)
    fallback_suppressed = 0
    fallback_added = 0
    for segment in fallback_segments:
        path = str(segment["path"])
        task_ids = set(focus_paths.get(path, ()))
        if not task_ids:
            continue
        covered: list[tuple[int, int]] = []
        for existing in regions:
            if existing.path != path:
                continue
            overlap_start = max(existing.start_line, int(segment["start_line"]))
            overlap_end = min(existing.end_line, int(segment["end_line"]))
            if overlap_start <= overlap_end:
                existing.task_ids.update(task_ids)
                _enrich_region_requirements(existing, plan)
                covered.append((overlap_start, overlap_end))
        uncovered = _subtract_covered_ranges(
            int(segment["start_line"]),
            int(segment["end_line"]),
            covered,
        )
        if not uncovered:
            fallback_suppressed += 1
            continue
        if covered:
            fallback_suppressed += 1
        for start_line, end_line in uncovered:
            fallback = _region_from_range(
                root,
                graph,
                path,
                start_line,
                end_line,
                task_ids=task_ids,
            )
            if fallback is None:
                continue
            _enrich_region_requirements(fallback, plan)
            regions.append(fallback)
            fallback_added += 1

    if stats is not None:
        stats["fallback_regions_requested"] = fallback_requested
        stats["fallback_regions_suppressed"] = fallback_suppressed
        stats["fallback_regions_added"] = fallback_added
        stats["regions"] = len(regions)

    return sorted(regions, key=lambda item: (item.path, item.start_line, item.end_line, item.anchor_id))


def _is_sensitive_path(path: Path) -> bool:
    name = path.name.lower()
    return name.startswith(".env") or any(
        term in name for term in ("credential", "secret", "id_rsa", "service-account")
    )


_DISCOVERY_CONTEXT_SEARCH_KINDS = {
    "references",
    "readers",
    "writers",
    "middleware",
    "authorization_decision",
    "security_control",
    "configuration",
    "environment_usage",
    "store_relationship",
    "credential_consumer",
}


def _context_request_key(request: Mapping[str, Any]) -> str:
    return _stable_hash({str(key): request[key] for key in sorted(request)})


def _has_context_evidence(result: Mapping[str, Any]) -> bool:
    if not bool(result.get("resolved")):
        return False
    return any(
        bool(result.get(key))
        for key in ("content", "edges", "definitions", "imports", "routes", "matches", "entries")
    )


def _source_windows_from_context(context_packets: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return only broker records whose actual source text was included in a prompt."""
    windows: list[dict[str, Any]] = []
    for packet in context_packets:
        if packet.get("content") and packet.get("path"):
            content = str(packet["content"])
            visible_lines = [
                int(number.strip())
                for source_line in content.splitlines()
                for number, separator, _text in [source_line.partition(":")]
                if separator and number.strip().isdigit()
            ]
            start = min(visible_lines) if visible_lines else int(
                packet.get("start_line", packet.get("line", 1)) or 1
            )
            end = max(visible_lines) if visible_lines else int(
                packet.get("end_line", start) or start
            )
            if end >= start:
                windows.append({"path": str(packet["path"]), "start_line": start, "end_line": end})
        for collection_name in ("edges", "definitions", "routes", "matches"):
            records = packet.get(collection_name, [])
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, Mapping) or not record.get("content"):
                    continue
                path = str(record.get("path", ""))
                if not path:
                    continue
                content = str(record["content"])
                visible_lines = []
                for source_line in content.splitlines():
                    number, separator, _text = source_line.partition(":")
                    if separator and number.strip().isdigit():
                        visible_lines.append(int(number.strip()))
                start = min(visible_lines) if visible_lines else int(
                    record.get("line", record.get("start_line", 1)) or 1
                )
                end = max(visible_lines) if visible_lines else int(
                    record.get("end_line", start) or start
                )
                if end >= start:
                    windows.append({"path": path, "start_line": start, "end_line": end})
    return windows


def _add_context_source_windows(
    root: Path,
    result: dict[str, Any],
    *,
    source_excludes: list[str],
    max_file_bytes: int | None,
) -> dict[str, Any]:
    runtime = load_json("runtime/agent.json")
    limit = int(runtime["discovery_context_per_request_max_characters"])
    used = 0
    enriched = dict(result)
    for collection_name in ("edges", "definitions", "routes", "matches"):
        enriched_items: list[dict[str, Any]] = []
        for raw_item in result.get(collection_name, []):
            item = dict(raw_item)
            path = str(item.get("path", ""))
            line = int(item.get("line", item.get("start_line", 1)) or 1)
            end_line = int(item.get("end_line", line) or line)
            if path and used < limit:
                try:
                    content = _source_window(
                        root,
                        path,
                        line,
                        end_line,
                        exclude=source_excludes,
                        max_file_bytes=max_file_bytes,
                    )
                except (AIResponseError, OSError):
                    content = ""
                if content:
                    remaining = max(0, limit - used)
                    item["content"] = content[:remaining]
                    used += len(item["content"])
            enriched_items.append(item)
        if enriched_items:
            enriched[collection_name] = enriched_items
    enriched["context_characters"] = used
    return enriched


def _resolve_discovery_context_request(
    agent: "OptimizedPlaidNoxDeepHuntAgent",
    root: Path,
    request: dict[str, Any],
) -> dict[str, Any]:
    kind = str(request.get("kind", ""))
    result: dict[str, Any] | None = None
    if kind in _DISCOVERY_CONTEXT_SEARCH_KINDS:
        result = _resolve_ir_relationship_request(agent.security_graph, request)
    if result is None or not _has_context_evidence(result):
        normalized = dict(request)
        if kind in _DISCOVERY_CONTEXT_SEARCH_KINDS:
            normalized["kind"] = "search"
            normalized["pattern"] = str(request.get("pattern") or request.get("symbol") or "")
        fallback = _resolve_context_request(
            root,
            agent.security_graph,
            normalized,
            source_excludes=agent.source_excludes,
            max_file_bytes=agent.max_file_bytes,
            knowledge_store=agent.knowledge_coordinator.store if agent.knowledge_coordinator else None,
        )
        if _has_context_evidence(fallback) or result is None:
            result = fallback
            result["resolution_source"] = "ripgrep_fallback" if kind in _DISCOVERY_CONTEXT_SEARCH_KINDS else "context_resolver"
    assert result is not None
    result["requested_kind"] = kind
    return _add_context_source_windows(
        root,
        result,
        source_excludes=agent.source_excludes,
        max_file_bytes=agent.max_file_bytes,
    )


def _resolve_ir_relationship_request(
    graph: StructuralGraph | None,
    request: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Resolve typed relationship requests from indexed structure before text search.

    The current Security IR records syntactic references, not taint direction or
    dataflow. Consequently readers/writers are returned as reference occurrences
    with their observed role explicitly labeled, never asserted as proven flows.
    """
    if graph is None:
        return None
    kind = str(request.get("kind", ""))
    symbol = str(request.get("symbol") or request.get("pattern") or "").strip()
    if not symbol:
        return None

    def aliases(value: str) -> set[str]:
        clean = value.strip().strip("'\"` ")
        return {clean.casefold(), clean.rsplit(".", 1)[-1].casefold()}

    wanted = aliases(symbol)
    if kind == "middleware":
        route_records: list[dict[str, Any]] = []
        for reference in graph.references:
            if not (aliases(reference.target) & wanted or aliases(reference.source) & wanted):
                continue
            matching_routes = [
                route for route in graph.routes
                if route.path == reference.path and route.line <= reference.line <= (route.end_line or route.line)
            ]
            for route in matching_routes:
                route_records.append({
                    "name": route.name,
                    "path": route.path,
                    "line": route.line,
                    "end_line": route.end_line or route.line,
                    "middleware_symbol": symbol,
                    "relationship": "route_reference_in_span",
                })
        # A call edge on the same route span also represents a structural
        # attachment candidate when parser references are unavailable.
        if not route_records:
            for call in graph.calls:
                if not (aliases(call.callee) & wanted):
                    continue
                for route in graph.routes:
                    if route.path == call.path and route.line <= call.line <= (route.end_line or route.line):
                        route_records.append({
                            "name": route.name, "path": route.path, "line": route.line,
                            "end_line": route.end_line or route.line,
                            "middleware_symbol": symbol,
                            "relationship": "route_call_in_span",
                        })
        if route_records:
            return {"kind": kind, "symbol": symbol, "resolved": True,
                    "routes": route_records, "resolution_source": "security_ir"}

    references = [
        {
            "path": item.path,
            "line": item.line,
            "source": item.source,
            "target": item.target,
            "relationship": "reference",
            "requested_relation": kind,
            "direction_proven": False,
        }
        for item in graph.references
        if aliases(item.target) & wanted or aliases(item.source) & wanted
    ]
    if kind in {"readers", "writers", "references", "authorization_decision", "security_control",
                "configuration", "environment_usage", "store_relationship", "credential_consumer"} and references:
        return {"kind": kind, "symbol": symbol, "resolved": True,
                "matches": references, "resolution_source": "security_ir"}
    return None


def _continuation_is_exceptional(
    region: DiscoveryRegion,
    context: AIRepositoryContext,
) -> bool:
    obligation_types = {item.obligation_type for item in region.obligation_specs.values()}
    return (
        bool(context.trust_boundaries)
        and bool(context.sensitive_effects)
        and bool(obligation_types & {"security_invariant", "sensitive_effect"})
    )


def _candidate_summary(candidate: Candidate) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate.metadata.get("candidate_id", "")),
        "root_cause": dict(candidate.metadata.get("root_cause") or {}),
        "attacker_influence": str(candidate.metadata.get("attacker_influence", "")),
        "broken_invariant": str(candidate.metadata.get("broken_invariant", "")),
        "gained_capability": str(candidate.metadata.get("gained_capability", "")),
        "path": candidate.evidence.path,
        "start_line": candidate.evidence.start_line,
        "end_line": candidate.evidence.end_line,
    }


def _validate_obligation_evidence(
    root: Path,
    results: list[dict[str, Any]],
    *,
    source_excludes: list[str],
    max_file_bytes: int | None,
) -> None:
    for result in results:
        for evidence in result["evidence"]:
            relative = str(evidence["path"])
            target = (root / relative).resolve()
            if (
                root.resolve() not in target.parents
                or not source_file_is_admitted(
                    root,
                    target,
                    exclude=source_excludes,
                    max_file_bytes=max_file_bytes,
                )
            ):
                raise AIResponseError("obligation result cited an inadmissible evidence path")
            start = int(evidence["start_line"])
            end = int(evidence["end_line"])
            line_count = len(target.read_text(encoding="utf-8", errors="replace").splitlines())
            if start < 1 or end < start or end > line_count:
                raise AIResponseError("obligation result cited an invalid evidence line range")


class OptimizedPlaidNoxDeepHuntAgent(PlaidNoxDeepHuntAgent):
    """Deep Hunt with structural, coverage-aware, resumable candidate discovery."""

    def discover_candidates(
        self,
        root: Path,
        context: AIRepositoryContext,
        plan: HuntPlan | None = None,
    ) -> tuple[list[Candidate], int]:
        if plan is None:
            raise AIResponseError("A hunt plan is required before candidate discovery")

        candidates: list[Candidate] = []
        failures = 0
        self.discovery_error_types = []
        self.discovery_errors = []
        self.discovery_unexpected_failures = 0
        self.discovery_contract_failures = 0
        self.discovery_metrics = {}
        self.discovery_unresolved_obligations = 0
        runtime = load_json("runtime/agent.json")
        queries = self._create_search_plan(context, plan)
        search_errors: list[RipgrepQueryError] = []
        region_stats: dict[str, int] = {}
        regions = _search_discovery_regions(
            root,
            queries,
            plan,
            self.security_graph,
            self.source_excludes,
            self.max_file_bytes,
            include_paths=set(context.analysis_scope_paths) or None,
            error_sink=search_errors.append,
            stats=region_stats,
        )
        self._emit("discovery_regions_planned", **region_stats)
        self._record_search_query_errors("candidate_discovery", context, search_errors)
        if not regions:
            raise AIResponseError("AI ripgrep plan produced no reviewable context")

        candidate_index = CandidateIndex()
        prompt_manifest = load_json("prompts/manifest.json")
        prompt_version = str(
            prompt_manifest["operations"]["vulnerability_discovery"].get(
                "contract_version", prompt_manifest["version"]
            )
        )
        telemetry = {
            "regions_planned": len(regions),
            "initial_region_calls": 0,
            "discovery_model_calls": 0,
            "checkpoint_discovery_hits": 0,
            "obligations_total": sum(len(region.obligation_specs) for region in regions),
            "obligations_no_issue": 0,
            "obligations_not_applicable": 0,
            "obligations_candidate_found": 0,
            "obligations_needs_context": 0,
            "obligations_unresolved": 0,
            "candidate_grounding_rejections": 0,
            "canonical_obligations_total": 0,
            "canonical_required_obligations": 0,
            "canonical_required_unresolved": 0,
            "canonical_supporting_unresolved": 0,
            "obligations_reconciled_by_sibling": 0,
            "discovery_contract_failures": 0,
            "context_requests_total": 0,
            "context_requests_unique": 0,
            "context_requests_resolved": 0,
            "context_requests_empty": 0,
            "context_requests_deferred": 0,
            "continuations_requested": 0,
            "continuations_executed": 0,
            "continuations_blocked_no_new_context": 0,
            "initial_input_characters": 0,
            "continuation_input_characters": 0,
            "candidates_raw": 0,
            "candidates_semantic_unique": 0,
            "candidate_evidence_merges": 0,
        }
        telemetry_lock = threading.Lock()

        def bump(key: str, amount: int = 1) -> None:
            with telemetry_lock:
                telemetry[key] += amount

        def analyze(
            region: DiscoveryRegion,
        ) -> tuple[list[Candidate], list[Exception], list[dict[str, Any]]]:
            segment = region.to_segment()
            segment_candidates: list[Candidate] = []
            errors: list[Exception] = []
            checkpoint_key = region.checkpoint_key(prompt_version)
            if self.checkpoint is not None:
                saved = self.checkpoint.get("discovery", checkpoint_key)
                if saved is not None:
                    bump("checkpoint_discovery_hits")
                    bump(
                        "discovery_contract_failures",
                        len(saved.get("coverage_state", {}).get("contract_issues", [])),
                    )
                    for disposition in saved.get("coverage_state", {}).get("dispositions", []):
                        status = str(disposition.get("status", ""))
                        metric = {
                            ObligationStatus.NO_ISSUE.value: "obligations_no_issue",
                            ObligationStatus.NOT_APPLICABLE.value: "obligations_not_applicable",
                            ObligationStatus.CANDIDATE_FOUND.value: "obligations_candidate_found",
                            ObligationStatus.NEEDS_CONTEXT.value: "obligations_needs_context",
                            ObligationStatus.UNRESOLVED.value: "obligations_unresolved",
                        }.get(status)
                        if metric:
                            bump(metric)
                    bump(
                        "obligations_needs_context",
                        len(saved.get("coverage_state", {}).get("needs_context_ids", [])),
                    )
                    self._emit(
                        "checkpoint_reused",
                        stage="discovery",
                        region_id=region.region_id,
                        path=region.path,
                        start_line=region.start_line,
                    )
                    saved_coverage = saved.get("coverage_state", {})
                    return (
                        [candidate_from_dict(item) for item in saved["candidates"]],
                        [],
                        _coverage_observations(saved_coverage),
                    )

            self._emit(
                "source_region_started",
                region_id=region.region_id,
                path=region.path,
                start_line=region.start_line,
                end_line=region.end_line,
                anchor_type=region.anchor_type,
                anchor_id=region.anchor_id,
            )
            related_tasks = [
                _region_task_payload(task, region)
                for task in _tasks_relevant_to_region(region, plan)
            ]
            coverage_state = DiscoveryCoverageState(region.region_id, dict(region.obligation_specs))
            rejected_candidate_ids: set[str] = set()
            resolved_context: list[dict[str, Any]] = []
            all_resolved_context: list[dict[str, Any]] = []
            maximum = (
                int(runtime["discovery_critical_max_continuations"])
                if _continuation_is_exceptional(region, context)
                else int(runtime["discovery_max_continuations"])
            )
            initial_latency_ms = 0
            continuation_latency_ms = 0

            for round_index in range(maximum + 1):
                if round_index > 0:
                    bump("continuations_executed")
                    active_ids = coverage_state.unresolved_ids()
                    request = {
                        "discovery_region": {
                            "region_id": region.region_id,
                            "path": region.path,
                            "anchor_type": region.anchor_type,
                            "anchor_id": region.anchor_id,
                            "start_line": region.start_line,
                            "end_line": region.end_line,
                        },
                        "root_cause_summary": [_candidate_summary(item) for item in segment_candidates],
                        "security_obligations": [
                            coverage_state.obligations[obligation_id].to_dict()
                            for obligation_id in active_ids
                        ],
                        "previous_dispositions": [
                            coverage_state.dispositions[obligation_id]
                            for obligation_id in active_ids
                            if obligation_id in coverage_state.dispositions
                        ],
                        "new_context": resolved_context,
                    }
                    bump("continuation_input_characters", len(json.dumps(request, default=str)))
                else:
                    bump("initial_region_calls")
                    request = {
                        "repository_context": self._compact_context_for_discovery(context, region.path),
                        "hunt_plan": {"strategy": plan.strategy, "tasks": related_tasks},
                        "source_segment": segment,
                        "security_obligations": [
                            item.to_dict() for item in coverage_state.obligations.values()
                        ],
                        "previous_dispositions": [],
                        "new_context": [],
                    }
                    bump("initial_input_characters", len(json.dumps(request, default=str)))
                try:
                    bump("discovery_model_calls")
                    started_at = time.monotonic()
                    response = self._structured_response(
                        "plaidnox_vulnerability_discovery",
                        load_json("schemas/vulnerability_discovery.json"),
                        "vulnerability_discovery",
                        request,
                    )
                    from .llm import response_json

                    payload = response_json(response)
                    elapsed = round((time.monotonic() - started_at) * 1000)
                    if round_index:
                        continuation_latency_ms += elapsed
                    else:
                        initial_latency_ms = elapsed

                    raw_items = list(payload["candidates"])
                    bump("candidates_raw", len(raw_items))
                    valid_candidate_ids: set[str] = set()
                    for item in raw_items:
                        candidate = _candidate_from_ai_item(
                            root,
                            item,
                            segment,
                            allowed_source_windows=_source_windows_from_context(all_resolved_context),
                        )
                        if candidate is None:
                            candidate_id = str(item.get("candidate_id", ""))
                            if candidate_id:
                                rejected_candidate_ids.add(candidate_id)
                                bump("candidate_grounding_rejections")
                            continue
                        candidate_id = str(item["candidate_id"])
                        candidate.metadata["candidate_id"] = candidate_id
                        if all_resolved_context:
                            candidate.metadata["discovery_context"] = list(all_resolved_context)
                        valid_candidate_ids.add(candidate_id)
                        if not candidate_index.admit(candidate):
                            bump("candidate_evidence_merges")
                            continue
                        segment_candidates.append(candidate)
                        bump("candidates_semantic_unique")

                    obligation_results = list(payload["obligation_results"])
                    _validate_obligation_evidence(
                        root,
                        obligation_results,
                        source_excludes=self.source_excludes,
                        max_file_bytes=self.max_file_bytes,
                    )
                    prior_contract_issues = len(coverage_state.contract_issues)
                    coverage_state.apply(
                        obligation_results,
                        coverage_state.candidate_ids | valid_candidate_ids,
                        rejected_candidate_ids,
                    )
                    contract_failures = len(coverage_state.contract_issues) - prior_contract_issues
                    if contract_failures:
                        bump("discovery_contract_failures", contract_failures)
                    needs_context = coverage_state.unresolved_ids()
                    if not needs_context:
                        break
                    bump("continuations_requested")
                    if round_index >= maximum:
                        coverage_state.mark_unresolved(needs_context, "continuation budget exhausted")
                        break

                    requests = [
                        dict(request_item)
                        for obligation_id in needs_context
                        for request_item in coverage_state.dispositions[obligation_id]["context_requests"]
                    ]
                    bump("context_requests_total", len(requests))
                    request_policy = load_json("runtime/agent.json")
                    priority = request_policy["discovery_context_request_priority"]
                    unique_requests = {
                        _context_request_key(item): item for item in requests
                    }
                    requests = sorted(
                        unique_requests.values(),
                        key=lambda item: (
                            int(priority.get(str(item.get("kind", "")), 100)),
                            _context_request_key(item),
                        ),
                    )
                    request_limit = int(request_policy["discovery_context_requests_per_expansion"])
                    bump("context_requests_deferred", max(0, len(requests) - request_limit))
                    requests = requests[:request_limit]
                    new_context: list[dict[str, Any]] = []
                    new_context_characters = 0
                    context_limit = int(runtime["discovery_context_max_characters"])
                    for context_request in requests:
                        request_key = _context_request_key(context_request)
                        if request_key in coverage_state.requested_context:
                            continue
                        coverage_state.requested_context.add(request_key)
                        bump("context_requests_unique")
                        resolved = _resolve_discovery_context_request(self, root, context_request)
                        if not _has_context_evidence(resolved):
                            bump("context_requests_empty")
                            continue
                        evidence_key = _stable_hash(resolved)
                        if evidence_key in coverage_state.resolved_context:
                            continue
                        context_characters = int(resolved.get("context_characters", 0))
                        if new_context and new_context_characters + context_characters > context_limit:
                            break
                        coverage_state.resolved_context.add(evidence_key)
                        new_context.append(resolved)
                        new_context_characters += context_characters
                        bump("context_requests_resolved")
                    if not new_context:
                        coverage_state.mark_unresolved(
                            needs_context,
                            "context broker produced no new evidence",
                        )
                        bump("continuations_blocked_no_new_context")
                        self._emit(
                            "discovery_continuation_blocked_no_new_context",
                            region_id=region.region_id,
                            path=region.path,
                            obligations=needs_context,
                        )
                        break
                    resolved_context = new_context
                    all_resolved_context.extend(new_context)
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    break

            for candidate in segment_candidates:
                if coverage_state.resolved_context:
                    candidate.metadata["discovery_context"] = all_resolved_context
            if not errors and not coverage_state.complete:
                errors.append(AIResponseError("discovery region retained non-terminal obligations"))

            final_statuses = [
                str(result["status"]) for result in coverage_state.dispositions.values()
            ]
            bump("obligations_no_issue", final_statuses.count(ObligationStatus.NO_ISSUE.value))
            bump(
                "obligations_not_applicable",
                final_statuses.count(ObligationStatus.NOT_APPLICABLE.value),
            )
            bump(
                "obligations_candidate_found",
                final_statuses.count(ObligationStatus.CANDIDATE_FOUND.value),
            )
            bump(
                "obligations_needs_context",
                len(coverage_state.needs_context_ids),
            )
            bump(
                "obligations_unresolved",
                final_statuses.count(ObligationStatus.UNRESOLVED.value),
            )

            if self.checkpoint is not None and not errors:
                self.checkpoint.put(
                    "discovery",
                    checkpoint_key,
                    {
                        "candidates": [candidate_to_dict(item) for item in segment_candidates],
                        "coverage_state": coverage_state.to_dict(),
                    },
                )
            self._emit(
                "source_region_completed",
                region_id=region.region_id,
                path=region.path,
                start_line=region.start_line,
                end_line=region.end_line,
                candidates=len(segment_candidates),
                errors=len(errors),
                obligations=len(coverage_state.obligations),
                initial_latency_milliseconds=initial_latency_ms,
                continuation_latency_milliseconds=continuation_latency_ms,
                context_requests=len(coverage_state.requested_context),
                new_context_characters=sum(
                    int(item.get("context_characters", 0)) for item in all_resolved_context
                ),
                stop_reason=(
                    "error"
                    if errors
                    else "unresolved_obligations"
                    if any(
                        result["status"] == ObligationStatus.UNRESOLVED.value
                        for result in coverage_state.dispositions.values()
                    )
                    else "obligations_terminal"
                    if coverage_state.complete
                    else "incomplete"
                ),
            )
            return segment_candidates, errors, _coverage_observations(coverage_state.to_dict())

        with ThreadPoolExecutor(max_workers=int(runtime["discovery_max_workers"])) as executor:
            all_observations: list[dict[str, Any]] = []
            for segment_candidates, errors, observations in executor.map(analyze, regions):
                candidates.extend(segment_candidates)
                all_observations.extend(observations)
                failures += len(errors)
                self.discovery_error_types.extend(type(error).__name__ for error in errors)
                self.discovery_errors.extend(str(error)[:240] for error in errors)
                self.discovery_unexpected_failures += sum(
                    1 for error in errors if not isinstance(error, AIStageError)
                )

        telemetry["discovery_model_calls_per_unique_region"] = round(
            telemetry["discovery_model_calls"] / max(1, len(regions)), 3
        )
        telemetry.update(reconcile_obligations(all_observations))
        self.discovery_metrics = dict(region_stats) | dict(telemetry)
        self.discovery_contract_failures = int(telemetry["discovery_contract_failures"])
        self.discovery_unresolved_obligations = int(telemetry["obligations_unresolved"])
        self.discovery_required_coverage_unresolved = int(
            telemetry["canonical_required_unresolved"]
        )
        self._emit("discovery_telemetry", **region_stats, **telemetry)
        return candidates, failures

    @staticmethod
    def _compact_context_for_discovery(
        context: AIRepositoryContext,
        focus_path: str,
    ) -> dict[str, Any]:
        # Keep the private helper import local so this layer remains narrow and
        # can be deleted once these semantics move into the base agent.
        from .ai import _compact_repository_context

        return _compact_repository_context(context, focus_path)
