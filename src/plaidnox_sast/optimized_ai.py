"""Discovery correctness/efficiency layer for PlaidNox Deep Hunt.

This module keeps the stable Deep Hunt verifier in :mod:`plaidnox_sast.ai` and
overrides only candidate discovery. The discovery identity is structural and
semantic: source content + Security IR + security obligations, never transient
planner/query identifiers.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .ai import (
    AIRepositoryContext,
    AIResponseError,
    HuntPlan,
    PlaidNoxDeepHuntAgent,
    _candidate_from_ai_item,
    _enclosing_symbol,
    _related_ir,
    _source_segments,
    _tasks_for_segment,
)
from .assets import load_json
from .checkpoint import candidate_from_dict, candidate_to_dict, unit_key
from .errors import AIStageError
from .fingerprint import CandidateIndex
from .graph import RipgrepDiscovery, RipgrepQueryError, SearchHit, StructuralGraph, source_files
from .models import Candidate
from .redaction import redact


def _stable_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


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
                "obligations": sorted(self.obligations),
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
            "vulnerability_themes": sorted(self.vulnerability_themes),
            "security_ir_slice": self.security_ir_slice,
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
    selected = [task for task in plan.tasks if task.task_id in region.task_ids]
    if not selected:
        selected = plan.tasks
    for task in selected:
        region.obligations.update(str(item) for item in task.coverage_obligations)
        region.vulnerability_themes.update(str(item) for item in task.vulnerability_themes)


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


def _discovery_progress(
    payload: Mapping[str, Any],
    *,
    new_candidates: int,
    previous_obligations: set[str],
    previous_branches: set[str],
    seen_focuses: set[str],
) -> tuple[bool, set[str], set[str], str]:
    coverage = payload.get("coverage") or {}
    obligations = {
        str(item) for item in coverage.get("obligations_reviewed", []) if str(item).strip()
    }
    branches = {str(item) for item in coverage.get("branches_reviewed", []) if str(item).strip()}
    next_focus = str(payload.get("next_focus", "")).strip()
    progressed = (
        new_candidates > 0
        or bool(obligations - previous_obligations)
        or bool(branches - previous_branches)
        or (bool(next_focus) and next_focus not in seen_focuses)
    )
    return progressed, obligations, branches, next_focus


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
        prompt_version = str(load_json("prompts/manifest.json")["version"])
        telemetry = {
            "discovery_model_calls": 0,
            "checkpoint_discovery_hits": 0,
            "continuations_requested": 0,
            "continuations_executed": 0,
            "continuations_no_progress": 0,
            "candidates_raw": 0,
            "candidates_unique": 0,
            "candidate_duplicates_absorbed": 0,
        }
        telemetry_lock = threading.Lock()

        def bump(key: str, amount: int = 1) -> None:
            with telemetry_lock:
                telemetry[key] += amount

        def analyze(region: DiscoveryRegion) -> tuple[list[Candidate], list[Exception]]:
            segment = region.to_segment()
            segment_candidates: list[Candidate] = []
            errors: list[Exception] = []
            checkpoint_key = region.checkpoint_key(prompt_version)
            if self.checkpoint is not None:
                saved = self.checkpoint.get("discovery", checkpoint_key)
                if saved is not None:
                    bump("checkpoint_discovery_hits")
                    self._emit(
                        "checkpoint_reused",
                        stage="discovery",
                        region_id=region.region_id,
                        path=region.path,
                        start_line=region.start_line,
                    )
                    return [candidate_from_dict(item) for item in saved["candidates"]], []

            self._emit(
                "source_region_started",
                region_id=region.region_id,
                path=region.path,
                start_line=region.start_line,
                end_line=region.end_line,
                anchor_type=region.anchor_type,
                anchor_id=region.anchor_id,
            )
            related_tasks = _tasks_for_segment(plan, region.path, region.task_ids)
            next_focus = ""
            seen_focuses: set[str] = set()
            reviewed_obligations: set[str] = set()
            reviewed_branches: set[str] = set()
            max_continuations = int(runtime["discovery_max_continuations"])

            for round_index in range(max_continuations + 1):
                if round_index > 0:
                    bump("continuations_executed")
                request = {
                    "repository_context": self._compact_context_for_discovery(context, region.path),
                    "hunt_plan": {"strategy": plan.strategy, "tasks": related_tasks},
                    "source_segment": segment,
                    "continuation_focus": next_focus,
                }
                try:
                    bump("discovery_model_calls")
                    response = self._structured_response(
                        "plaidnox_vulnerability_discovery",
                        load_json("schemas/vulnerability_discovery.json"),
                        "vulnerability_discovery",
                        request,
                    )
                    from .llm import response_json

                    payload = response_json(response)

                    raw_items = list(payload["candidates"])
                    bump("candidates_raw", len(raw_items))
                    new_candidates = 0
                    for item in raw_items:
                        candidate = _candidate_from_ai_item(root, item, segment)
                        if candidate is None:
                            continue
                        if not candidate_index.admit(candidate):
                            bump("candidate_duplicates_absorbed")
                            continue
                        segment_candidates.append(candidate)
                        new_candidates += 1
                        bump("candidates_unique")

                    if bool(payload["coverage_complete"]):
                        break

                    progressed, obligations, branches, proposed_focus = _discovery_progress(
                        payload,
                        new_candidates=new_candidates,
                        previous_obligations=reviewed_obligations,
                        previous_branches=reviewed_branches,
                        seen_focuses=seen_focuses,
                    )
                    reviewed_obligations.update(obligations)
                    reviewed_branches.update(branches)

                    if not proposed_focus:
                        raise AIResponseError(
                            "AI marked coverage incomplete without a continuation focus"
                        )
                    bump("continuations_requested")
                    if round_index >= max_continuations:
                        break
                    if not progressed:
                        bump("continuations_no_progress")
                        self._emit(
                            "discovery_continuation_no_progress",
                            region_id=region.region_id,
                            path=region.path,
                            round=round_index,
                        )
                        break
                    if proposed_focus in seen_focuses and new_candidates == 0:
                        bump("continuations_no_progress")
                        self._emit(
                            "discovery_continuation_repeated_focus",
                            region_id=region.region_id,
                            path=region.path,
                            round=round_index,
                        )
                        break
                    seen_focuses.add(proposed_focus)
                    next_focus = proposed_focus
                except Exception as exc:  # noqa: BLE001
                    errors.append(exc)
                    break

            if self.checkpoint is not None and not errors:
                self.checkpoint.put(
                    "discovery",
                    checkpoint_key,
                    {"candidates": [candidate_to_dict(item) for item in segment_candidates]},
                )
            sink = self.candidate_sink
            if sink is not None and not errors:
                for candidate in segment_candidates:
                    try:
                        sink(candidate)
                    except Exception:  # noqa: BLE001
                        break
            self._emit(
                "source_region_completed",
                region_id=region.region_id,
                path=region.path,
                start_line=region.start_line,
                end_line=region.end_line,
                candidates=len(segment_candidates),
                errors=len(errors),
            )
            return segment_candidates, errors

        with ThreadPoolExecutor(max_workers=int(runtime["discovery_max_workers"])) as executor:
            for segment_candidates, errors in executor.map(analyze, regions):
                candidates.extend(segment_candidates)
                failures += len(errors)
                self.discovery_error_types.extend(type(error).__name__ for error in errors)
                self.discovery_errors.extend(str(error)[:240] for error in errors)
                self.discovery_unexpected_failures += sum(
                    1 for error in errors if not isinstance(error, AIStageError)
                )

        telemetry["discovery_model_calls_per_unique_region"] = round(
            telemetry["discovery_model_calls"] / max(1, len(regions)), 3
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
