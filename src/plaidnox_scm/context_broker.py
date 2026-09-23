"""Candidate-specific, bounded Layer-2 context expansion."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

from plaidnox_sast.graph import Call, Reference, RipgrepDiscovery, StructuralGraph, Symbol
from plaidnox_sast.redaction import redact

from .assets import load_json
from .context_store import ApplicationContext
from .l1_review import ExpansionRequest, L1Candidate


@dataclass(frozen=True, slots=True)
class ExpansionEvidence:
    kind: str
    target: str
    reason: str
    resolved: bool
    records: tuple[dict[str, Any], ...]
    gap: str = ""


@dataclass(frozen=True, slots=True)
class CandidateContextExpansion:
    candidate_id: str
    evidence: tuple[ExpansionEvidence, ...]

    @property
    def complete(self) -> bool:
        return all(item.resolved for item in self.evidence)

    @property
    def unresolved_gaps(self) -> tuple[str, ...]:
        return tuple(item.gap for item in self.evidence if not item.resolved and item.gap)

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "complete": self.complete,
            "evidence": [asdict(item) for item in self.evidence],
            "unresolved_gaps": list(self.unresolved_gaps),
        }

    def to_prompt_dict(self, maximum_characters: int) -> dict[str, Any]:
        """Keep request outcomes visible while bounding records sent to the verifier."""

        payload: dict[str, Any] = {
            "candidate_id": self.candidate_id,
            "complete": self.complete,
            "prompt_truncated": False,
            "omitted_requests": 0,
            "omitted_gaps": 0,
            "evidence": [],
            "unresolved_gaps": [],
        }
        for item in self.evidence:
            compact = {
                "kind": item.kind,
                "target": item.target,
                "reason": item.reason,
                "resolved": item.resolved,
                "records": [],
                "gap": item.gap,
            }
            payload["evidence"].append(compact)
            if _json_characters(payload) > maximum_characters:
                payload["evidence"].pop()
                payload["omitted_requests"] += 1
                payload["prompt_truncated"] = True
                continue
            for record in item.records:
                compact["records"].append(record)
                if _json_characters(payload) > maximum_characters:
                    compact["records"].pop()
                    payload["prompt_truncated"] = True
                    break
        for gap in self.unresolved_gaps:
            payload["unresolved_gaps"].append(gap)
            if _json_characters(payload) > maximum_characters:
                payload["unresolved_gaps"].pop()
                payload["omitted_gaps"] += 1
                payload["prompt_truncated"] = True
        return payload


class ContextBroker(Protocol):
    def expand(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
    ) -> CandidateContextExpansion: ...


class SCMContextBroker:
    """Resolve only the exact expansion requests emitted for one L1 candidate."""

    def expand(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
    ) -> CandidateContextExpansion:
        runtime = load_json("runtime/review.json")["context_broker"]
        limit = int(runtime["maximum_requests_per_candidate"])
        requests = candidate.requested_expansion[:limit]
        evidence = tuple(
            self._resolve(root, graph, candidate, application_context, request, runtime)
            for request in requests
        )
        if len(candidate.requested_expansion) > limit:
            evidence += (
                ExpansionEvidence(
                    kind="request_budget",
                    target=candidate.candidate_id,
                    reason="L1 requested more context than the configured candidate budget",
                    resolved=False,
                    records=(),
                    gap="Candidate context request budget was exceeded",
                ),
            )
        return CandidateContextExpansion(candidate.candidate_id, evidence)

    def _resolve(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> ExpansionEvidence:
        resolvers = {
            "definition": self._definition,
            "callers": self._callers,
            "callees": self._callees,
            "imports": self._imports,
            "route": self._route,
            "window": self._window,
            "sibling_handlers": self._sibling_handlers,
            "search": self._search,
            "flow": self._flow,
        }
        resolver = resolvers.get(request.kind)
        if resolver is None:
            return _unresolved(request, f"Unsupported candidate context request kind: {request.kind}")
        try:
            records = resolver(root, graph, candidate, application_context, request, runtime)
        except (OSError, RuntimeError, ValueError) as exc:
            return _unresolved(request, f"Context expansion failed: {type(exc).__name__}")
        if not records:
            return _unresolved(request, f"No evidence resolved for {request.kind}:{request.target}")
        maximum = int(runtime["maximum_records_per_request"])
        return ExpansionEvidence(
            kind=request.kind,
            target=request.target,
            reason=request.reason,
            resolved=True,
            records=tuple(records[:maximum]),
        )

    def _definition(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        # L1 is asked for an exact symbol but routinely sends a repository path
        # ("models/NST.js") or "path:symbol". Matching only symbol names left
        # every such request -- and so every candidate -- unresolved.
        path, symbol_name = _definition_target(request.target, graph)
        matches = [
            symbol
            for symbol in graph.symbols
            if (not symbol_name or _symbol_matches(symbol.name, symbol.qualified_name, symbol_name))
            and (path is None or symbol.path == path)
        ]
        if matches:
            return [_symbol_record(root, symbol, runtime) for symbol in matches]
        if path is not None:
            # The file is admitted but Tree-sitter extracted no matching symbol
            # (e.g. `const User = mongoose.model(...)`): return its head instead.
            return _file_head_records(root, path, runtime)
        return _declaration_records(root, graph, symbol_name, runtime)

    def _callers(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        calls = [call for call in graph.calls if _name_matches(call.callee, request.target)]
        if calls:
            return [_call_record(root, call, "caller", runtime) for call in calls]
        # Functions passed by reference (Express middleware: `app.get(p, authCheck, h)`,
        # callbacks, decorators) have no call edge, only identifier references.
        references = [
            reference
            for reference in graph.references
            if reference.kind == "identifier" and _name_matches(reference.target, request.target)
        ]
        return [_reference_record(root, reference, runtime) for reference in references]

    def _callees(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        calls = [call for call in graph.calls if _name_matches(call.caller, request.target)]
        return [_call_record(root, call, "callee", runtime) for call in calls]

    def _imports(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        file_ir = next((item for item in graph.files if item.path == request.target), None)
        if file_ir is None and request.target == candidate.changed_symbol:
            file_ir = next((item for item in graph.files if item.path == candidate.changed_path), None)
        if file_ir is None:
            return []
        return [
            {"path": file_ir.path, "kind": "import", "content": redact(value)}
            for value in file_ir.imports
        ]

    def _route(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        needle = request.target.casefold()
        records: list[dict[str, Any]] = []
        for route in graph.routes:
            if needle in route.name.casefold() or needle in route.path.casefold():
                records.append(_symbol_record(root, route, runtime))
        for source, values in (
            ("application_context.routes", application_context.routes),
            ("application_context.entry_points", application_context.entry_points),
        ):
            for value in values:
                rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
                if needle in rendered.casefold():
                    records.append({"kind": "route", "source": source, "content": redact(rendered)})
        return records

    def _window(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        path, start, end = _window_target(request.target, candidate)
        record = _source_record(root, path, start, end, runtime)
        return [record] if record else []

    def _sibling_handlers(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        path = request.target if "/" in request.target or "." in Path(request.target).name else candidate.changed_path
        matches = [symbol for symbol in graph.symbols if symbol.path == path]
        return [_symbol_record(root, symbol, runtime) for symbol in matches]

    def _search(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        hits = RipgrepDiscovery(root).search(candidate.candidate_id, request.target)
        return [
            {
                "kind": "search_hit",
                "path": hit.path,
                "start_line": hit.line,
                "end_line": hit.line,
                "content": redact(hit.text),
            }
            for hit in hits
        ]

    def _flow(
        self,
        root: Path,
        graph: StructuralGraph,
        candidate: L1Candidate,
        application_context: ApplicationContext,
        request: ExpansionRequest,
        runtime: dict[str, Any],
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for call in graph.calls:
            if _name_matches(call.caller, request.target) or _name_matches(call.callee, request.target):
                records.append(_call_record(root, call, "flow", runtime))
        return records


def _definition_target(target: str, graph: StructuralGraph) -> tuple[str | None, str]:
    """Split a definition target into (admitted graph path or None, symbol name)."""

    target = target.strip()
    known = {item.path for item in graph.files}
    if target in known:
        return target, ""
    for separator in ("#", ":"):
        path, _, name = target.rpartition(separator)
        if path in known and name and not name.isdigit():
            return path, name
    return None, target


def _file_head_records(root: Path, path: str, runtime: dict[str, Any]) -> list[dict[str, Any]]:
    span = int(runtime["context_lines_before"]) + int(runtime["context_lines_after"])
    record = _source_record(root, path, 1, span * 3, runtime)
    return [{"kind": "definition", "symbol": path, **record}] if record else []


def _declaration_records(
    root: Path,
    graph: StructuralGraph,
    name: str,
    runtime: dict[str, Any],
) -> list[dict[str, Any]]:
    """Find `const|let|var|class|function NAME` bindings Tree-sitter did not index."""

    if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
        return []
    declaration = re.compile(rf"\b(?:const|let|var|class|function|def)\s+{re.escape(name)}\b")
    maximum = int(runtime["maximum_records_per_request"])
    records: list[dict[str, Any]] = []
    for file_ir in graph.files:
        target = root.resolve() / file_ir.path
        try:
            lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            if declaration.search(line):
                record = _source_record(root, file_ir.path, number, number, runtime)
                if record:
                    records.append({"kind": "definition", "symbol": name, **record})
                if len(records) >= maximum:
                    return records
    return records


def _symbol_matches(name: str, qualified_name: str, target: str) -> bool:
    return _name_matches(name, target) or _name_matches(qualified_name, target)


def _name_matches(value: str, target: str) -> bool:
    value_normalized = value.casefold().strip()
    target_normalized = target.casefold().strip()
    return value_normalized == target_normalized or value_normalized.endswith(f".{target_normalized}")


def _symbol_record(root: Path, symbol: Symbol, runtime: dict[str, Any]) -> dict[str, Any]:
    source = _source_record(root, symbol.path, symbol.line, symbol.end_line or symbol.line, runtime)
    return {
        "kind": "definition",
        "symbol": symbol.qualified_name or symbol.name,
        "path": symbol.path,
        "start_line": symbol.line,
        "end_line": symbol.end_line or symbol.line,
        "content": source["content"] if source else "",
    }


def _call_record(root: Path, call: Call, relationship: str, runtime: dict[str, Any]) -> dict[str, Any]:
    source = _source_record(root, call.path, call.line, call.line, runtime)
    return {
        "kind": "call_edge",
        "relationship": relationship,
        "caller": call.caller,
        "callee": call.callee,
        "path": call.path,
        "start_line": call.line,
        "end_line": call.line,
        "content": source["content"] if source else "",
    }


def _reference_record(root: Path, reference: Reference, runtime: dict[str, Any]) -> dict[str, Any]:
    source = _source_record(root, reference.path, reference.line, reference.line, runtime)
    return {
        "kind": "reference",
        "relationship": "caller",
        "symbol": reference.target,
        "path": reference.path,
        "start_line": reference.line,
        "end_line": reference.line,
        "content": source["content"] if source else "",
    }


def _source_record(
    root: Path,
    relative_path: str,
    start_line: int,
    end_line: int,
    runtime: dict[str, Any],
) -> dict[str, Any] | None:
    root = root.resolve()
    target = (root / relative_path).resolve()
    if root not in target.parents or not target.is_file():
        return None
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    before = int(runtime["context_lines_before"])
    after = int(runtime["context_lines_after"])
    first = max(1, start_line - before)
    last = min(len(lines), max(start_line, end_line) + after)
    content = "\n".join(f"{number}: {lines[number - 1]}" for number in range(first, last + 1))
    maximum = int(runtime["maximum_record_characters"])
    return {
        "path": relative_path,
        "start_line": first,
        "end_line": last,
        "content": redact(content[:maximum]),
    }


_WINDOW_TARGET = re.compile(r"^(?P<path>[^:]+)(?::(?P<start>\d+)(?:-(?P<end>\d+))?)?$")


def _window_target(target: str, candidate: L1Candidate) -> tuple[str, int, int]:
    match = _WINDOW_TARGET.fullmatch(target.strip())
    if match is None:
        raise ValueError("Invalid window target")
    path = match.group("path") or candidate.changed_path
    start = int(match.group("start") or candidate.changed_lines.start)
    end = int(match.group("end") or start)
    if start < 1 or end < start:
        raise ValueError("Invalid window line range")
    return path, start, end


def _unresolved(request: ExpansionRequest, gap: str) -> ExpansionEvidence:
    return ExpansionEvidence(
        kind=request.kind,
        target=request.target,
        reason=request.reason,
        resolved=False,
        records=(),
        gap=gap,
    )


def _json_characters(value: dict[str, Any]) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str))
