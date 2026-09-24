"""Lightweight cached Security IR built with Tree-sitter.

The module keeps a compatibility name (`StructuralGraph`) for existing scanner
adapters. Tree-sitter provides symbol/call structure. AI-planned search is a
separate orchestration stage; this index contains no baked-in security searches
and never produces a vulnerability verdict.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .assets import load_json
from .redaction import redact


class RipgrepQueryError(RuntimeError):
    """A single AI-generated query failed without making the executor unusable."""

    def __init__(self, query_id: str, pattern: str, diagnostic: str, exit_code: int | None = None) -> None:
        self.query_id = redact(query_id)
        self.pattern_hash = hashlib.sha256(pattern.encode("utf-8")).hexdigest()
        self.diagnostic = redact(diagnostic)
        self.exit_code = exit_code
        status = f"exit code {exit_code}" if exit_code is not None else "validation"
        super().__init__(f"ripgrep query {self.query_id!r} failed ({status}): {self.diagnostic}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "pattern_hash": self.pattern_hash,
            "exit_code": self.exit_code,
            "diagnostic": self.diagnostic,
        }


@dataclass(slots=True)
class Symbol:
    name: str
    path: str
    line: int
    end_line: int = 0
    kind: str = "symbol"
    qualified_name: str = ""
    signature: str = ""


@dataclass(slots=True)
class Call:
    caller: str
    callee: str
    path: str
    line: int


@dataclass(slots=True)
class Reference:
    source: str
    target: str
    path: str
    line: int
    kind: str


@dataclass(slots=True)
class SearchHit:
    query_id: str
    path: str
    line: int
    text: str


@dataclass(slots=True)
class FileSecurityIR:
    path: str
    language: str
    content_hash: str
    symbols: list[Symbol] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)


@dataclass(slots=True)
class StructuralGraph:
    symbols: list[Symbol] = field(default_factory=list)
    routes: list[Symbol] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    files: list[FileSecurityIR] = field(default_factory=list)
    search_hits: list[SearchHit] = field(default_factory=list)
    tree_sitter_files: int = 0
    fallback_files: int = 0
    rg_queries: int = 0

    def symbol_at(self, path: str, line: int) -> str:
        matches = [symbol for symbol in self.symbols + self.routes if symbol.path == path and symbol.line <= line]
        if not matches:
            return path
        return max(matches, key=lambda symbol: symbol.line).name

    def affected_surface(self, changed_paths: list[str]) -> dict[str, list[dict[str, object]] | list[str]]:
        changed = sorted(set(changed_paths))
        return {
            "changed_paths": changed,
            "routes": [
                {"name": route.name, "path": route.path, "line": route.line}
                for route in self.routes
                if route.path in changed
            ],
            "symbols": [
                {"name": symbol.name, "path": symbol.path, "line": symbol.line}
                for symbol in self.symbols
                if symbol.path in changed
            ],
        }


def source_files(
    root: Path,
    exclude: Iterable[str] | None = None,
    max_file_bytes: int | None = None,
) -> list[Path]:
    """Return eligible source/configuration files without executing target code."""

    root = root.resolve()
    config = load_json("code_intelligence/languages.json")
    extensions = {str(item).lower() for item in config["source_extensions"]}
    filenames = {str(item) for item in config["source_filenames"]}
    ignored_directories = {str(item) for item in config["ignored_directories"]}
    excluded = list(exclude or [])
    maximum = max_file_bytes if max_file_bytes is not None else int(config["default_max_file_bytes"])
    if maximum < 1:
        raise ValueError("max_file_bytes must be positive")
    files: list[Path] = []
    for path in root.rglob("*"):
        if _source_file_is_admitted(
            root,
            path,
            excluded,
            maximum,
            extensions,
            filenames,
            ignored_directories,
        ):
            files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def source_file_is_admitted(
    root: Path,
    path: Path,
    exclude: Iterable[str] | None = None,
    max_file_bytes: int | None = None,
) -> bool:
    """Check one path against the same source policy used by inventory and discovery."""

    root = root.resolve()
    config = load_json("code_intelligence/languages.json")
    maximum = max_file_bytes if max_file_bytes is not None else int(config["default_max_file_bytes"])
    if maximum < 1:
        raise ValueError("max_file_bytes must be positive")
    return _source_file_is_admitted(
        root,
        path,
        [str(item) for item in (exclude or [])],
        maximum,
        {str(item).lower() for item in config["source_extensions"]},
        {str(item) for item in config["source_filenames"]},
        {str(item) for item in config["ignored_directories"]},
    )


def _source_file_is_admitted(
    root: Path,
    path: Path,
    exclude: list[str],
    maximum: int,
    extensions: set[str],
    filenames: set[str],
    ignored_directories: set[str],
) -> bool:
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root).as_posix()
        resolved = candidate.resolve()
    except (OSError, ValueError):
        return False
    if root not in resolved.parents or not candidate.is_file():
        return False
    if ignored_directories.intersection(candidate.relative_to(root).parts):
        return False
    if exclude and any(fnmatch.fnmatch(relative, pattern) for pattern in exclude):
        return False
    if candidate.suffix.lower() not in extensions and candidate.name not in filenames:
        return False
    try:
        return candidate.stat().st_size <= maximum
    except OSError:
        return False


def readable_source_tree(
    root: Path,
    limit: int = 500,
    exclude: Iterable[str] | None = None,
    max_file_bytes: int | None = None,
) -> list[str]:
    if limit < 1:
        raise ValueError("limit must be positive")
    paths = [
        path.relative_to(root).as_posix()
        for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes)
    ]
    return paths[:limit]


class RipgrepDiscovery:
    """Safe, bounded ripgrep JSON adapter for AI-created discovery queries."""

    def __init__(
        self,
        root: Path,
        exclude: Iterable[str] = (),
        max_file_bytes: int | None = None,
    ) -> None:
        self.root = root.resolve()
        self.exclude = tuple(str(item) for item in exclude)
        config = load_json("code_intelligence/languages.json")
        self.max_file_bytes = (
            max_file_bytes
            if max_file_bytes is not None
            else int(config["default_max_file_bytes"])
        )
        if self.max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        if not shutil.which("rg"):
            raise RuntimeError("ripgrep is required for Code Scanning discovery")

    def search(
        self,
        query_id: str,
        pattern: str,
        include_globs: Iterable[str] = (),
        exclude_globs: Iterable[str] = (),
    ) -> list[SearchHit]:
        """Execute a regex query for trusted internal callers and compatibility."""

        return self._search(query_id, [pattern], include_globs, exclude_globs, fixed_strings=False)

    def search_literals(
        self,
        query_id: str,
        terms: Iterable[str],
        include_globs: Iterable[str] = (),
        exclude_globs: Iterable[str] = (),
    ) -> list[SearchHit]:
        """Execute AI-created search intent as fixed strings, never as regex code."""

        return self._search(query_id, list(terms), include_globs, exclude_globs, fixed_strings=True)

    def _search(
        self,
        query_id: str,
        patterns: list[str],
        include_globs: Iterable[str],
        exclude_globs: Iterable[str],
        *,
        fixed_strings: bool,
    ) -> list[SearchHit]:
        runtime = load_json("runtime/code_intelligence.json")
        maximum_terms = int(runtime["maximum_literal_terms_per_query"])
        if not patterns or len(patterns) > maximum_terms or any(
            not pattern
            or len(pattern) > int(runtime["maximum_pattern_characters"])
            or any(character in pattern for character in ("\r", "\n", "\0"))
            for pattern in patterns
        ):
            raise RipgrepQueryError(
                query_id,
                "\0".join(patterns),
                "query terms are empty or exceed the configured limits",
            )
        command = [
            "rg",
            "--json",
            "--line-number",
            "--no-config",
            "--hidden",
            "--max-filesize",
            str(self.max_file_bytes),
        ]
        if fixed_strings:
            command.append("--fixed-strings")
        languages = load_json("code_intelligence/languages.json")
        for extension in languages["source_extensions"]:
            command.extend(("--type-add", f"plaidnox:*{extension}"))
        for filename in languages["source_filenames"]:
            command.extend(("--type-add", f"plaidnox:{filename}"))
        command.extend(("--type", "plaidnox"))
        for value in include_globs:
            command.extend(("--glob", str(value)))
        for value in dict.fromkeys((*self.exclude, *(str(item) for item in exclude_globs))):
            command.extend(("--glob", f"!{value}"))
        for pattern in patterns:
            command.extend(("--regexp", pattern))
        command.extend(("--", "."))
        try:
            result = subprocess.run(
                command,
                cwd=self.root,
                text=True,
                capture_output=True,
                check=False,
                timeout=int(runtime["rg_timeout_seconds"]),
            )
        except subprocess.TimeoutExpired as exc:
            raise RipgrepQueryError(
                query_id,
                "\0".join(patterns),
                "query exceeded the configured execution timeout",
            ) from exc
        if result.returncode not in {0, 1}:
            diagnostic = " ".join((result.stderr or "ripgrep returned no diagnostic").split())
            maximum = int(runtime["maximum_rg_error_characters"])
            raise RipgrepQueryError(
                query_id,
                "\0".join(patterns),
                diagnostic[:maximum],
                result.returncode,
            )
        hits: list[SearchHit] = []
        limit = int(runtime["maximum_hits_per_query"])
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") != "match":
                continue
            data = event.get("data", {})
            raw_path = str(data.get("path", {}).get("text", ""))
            relative = raw_path.removeprefix("./")
            line_number = int(data.get("line_number", 0))
            text = str(data.get("lines", {}).get("text", "")).rstrip("\r\n")
            if relative and line_number > 0:
                hits.append(SearchHit(query_id, relative, line_number, text))
            if len(hits) >= limit:
                break
        return hits


def build_structural_graph(
    root: Path,
    exclude: Iterable[str] | None = None,
    max_file_bytes: int | None = None,
) -> StructuralGraph:
    """Build compact Security IR; Tree-sitter failure falls back per file."""

    root = root.resolve()
    graph = StructuralGraph()
    config = load_json("code_intelligence/languages.json")
    for path in source_files(root, exclude=exclude, max_file_bytes=max_file_bytes):
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_bytes()
        except OSError:
            continue
        language = _language_for(path, config)
        file_ir = _tree_sitter_ir(relative, language, content, config)
        if file_ir is None:
            file_ir = _fallback_ir(relative, language, content)
            graph.fallback_files += 1
        else:
            graph.tree_sitter_files += 1
        graph.files.append(file_ir)
        graph.symbols.extend(file_ir.symbols)
        graph.calls.extend(file_ir.calls)
        graph.references.extend(file_ir.references)

    return graph


def build_file_security_ir(
    root: Path,
    relative_path: str,
    max_file_bytes: int | None = None,
) -> FileSecurityIR | None:
    """Build Tree-sitter Security IR for one changed file without indexing the repository."""

    root = root.resolve()
    path = (root / relative_path).resolve()
    if root not in path.parents or not path.is_file():
        return None
    config = load_json("code_intelligence/languages.json")
    extensions = {str(item).lower() for item in config["source_extensions"]}
    filenames = {str(item) for item in config["source_filenames"]}
    if path.suffix.lower() not in extensions and path.name not in filenames:
        return None
    maximum = max_file_bytes if max_file_bytes is not None else int(config["default_max_file_bytes"])
    try:
        if path.stat().st_size > maximum:
            return None
        content = path.read_bytes()
    except OSError:
        return None
    language = _language_for(path, config)
    return _tree_sitter_ir(relative_path, language, content, config) or _fallback_ir(
        relative_path, language, content
    )


def _tree_sitter_ir(
    relative: str,
    language: str,
    content: bytes,
    config: dict[str, Any],
) -> FileSecurityIR | None:
    if not language:
        return None
    try:
        from tree_sitter_language_pack import get_parser

        parser = get_parser(language)
        tree = parser.parse(content)
    except (ImportError, LookupError, RuntimeError, ValueError):
        return None
    symbol_types = {str(item) for item in config["symbol_node_types"]}
    call_types = {str(item) for item in config["call_node_types"]}
    import_types = {str(item) for item in config["import_node_types"]}
    reference_types = {str(item) for item in config["reference_node_types"]}
    maximum_references = int(config["maximum_references_per_file"])
    symbols: list[Symbol] = []
    calls: list[Call] = []
    references: list[Reference] = []
    imports: list[str] = []

    def visit(node: Any, enclosing: str = "") -> None:
        current = enclosing
        if node.type in symbol_types:
            name_node = node.child_by_field_name("name")
            if name_node is None and node.parent is not None:
                name_node = node.parent.child_by_field_name("name")
            name = _node_text(name_node, content) if name_node is not None else ""
            if name:
                current = f"{enclosing}.{name}" if enclosing else name
                symbols.append(
                    Symbol(
                        name,
                        relative,
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                        node.type,
                        current,
                        _symbol_signature(node, content),
                    )
                )
        if node.type in import_types:
            imports.append(_node_text(node, content))
        if node.type in call_types:
            function_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            callee = _node_text(function_node, content) if function_node is not None else ""
            if callee:
                calls.append(Call(current or relative, callee, relative, node.start_point[0] + 1))
        if node.type in reference_types and len(references) < maximum_references:
            target = _node_text(node, content)
            parent_name = node.parent.child_by_field_name("name") if node.parent is not None else None
            is_definition_name = (
                node.parent is not None
                and node.parent.type in symbol_types
                and parent_name is not None
                and parent_name.start_byte == node.start_byte
                and parent_name.end_byte == node.end_byte
            )
            if target and not is_definition_name:
                references.append(
                    Reference(
                        current or relative,
                        target,
                        relative,
                        node.start_point[0] + 1,
                        node.type,
                    )
                )
        for child in node.children:
            visit(child, current)

    visit(tree.root_node)
    return FileSecurityIR(
        path=relative,
        language=language,
        content_hash=hashlib.sha256(content).hexdigest(),
        symbols=symbols,
        calls=calls,
        references=list(
            {
                (item.source, item.target, item.path, item.line, item.kind): item
                for item in references
            }.values()
        ),
        imports=list(dict.fromkeys(imports)),
    )


def _fallback_ir(
    relative: str,
    language: str,
    content: bytes,
) -> FileSecurityIR:
    text = content.decode("utf-8", errors="replace")
    name = Path(relative).as_posix()
    symbols = [Symbol(name, relative, 1, max(1, len(text.splitlines())), "file", name, "")]
    return FileSecurityIR(
        path=relative,
        language=language or "unknown",
        content_hash=hashlib.sha256(content).hexdigest(),
        symbols=symbols,
    )


def _language_for(path: Path, config: dict[str, Any]) -> str:
    filename_languages = {str(key): str(value) for key, value in config["filename_languages"].items()}
    if path.name in filename_languages:
        return filename_languages[path.name]
    return str(config["extension_languages"].get(path.suffix.lower(), ""))


def _node_text(node: Any, content: bytes) -> str:
    return content[node.start_byte : node.end_byte].decode("utf-8", errors="replace").strip()


def _symbol_signature(node: Any, content: bytes) -> str:
    """Return a body-independent structural signature for overloaded symbols."""

    body = node.child_by_field_name("body")
    end_byte = body.start_byte if body is not None else min(node.end_byte, node.start_byte + 2000)
    raw = content[node.start_byte:end_byte].decode("utf-8", errors="replace")
    return " ".join(raw.split())
