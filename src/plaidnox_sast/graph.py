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
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .assets import load_json


@dataclass(slots=True)
class Symbol:
    name: str
    path: str
    line: int
    end_line: int = 0
    kind: str = "symbol"
    qualified_name: str = ""


@dataclass(slots=True)
class Call:
    caller: str
    callee: str
    path: str
    line: int


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
    imports: list[str] = field(default_factory=list)


@dataclass(slots=True)
class StructuralGraph:
    symbols: list[Symbol] = field(default_factory=list)
    routes: list[Symbol] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
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

    config = load_json("code_intelligence/languages.json")
    extensions = {str(item).lower() for item in config["source_extensions"]}
    filenames = {str(item) for item in config["source_filenames"]}
    ignored_directories = {str(item) for item in config["ignored_directories"]}
    excluded = list(exclude or [])
    maximum = max_file_bytes if max_file_bytes is not None else int(config["default_max_file_bytes"])
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or ignored_directories.intersection(path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        if excluded and any(fnmatch.fnmatch(relative, pattern) for pattern in excluded):
            continue
        if path.suffix.lower() not in extensions and path.name not in filenames:
            continue
        try:
            if path.stat().st_size > maximum:
                continue
        except OSError:
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


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

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not shutil.which("rg"):
            raise RuntimeError("ripgrep is required for Code Scanning discovery")

    def search(
        self,
        query_id: str,
        pattern: str,
        include_globs: Iterable[str] = (),
        exclude_globs: Iterable[str] = (),
    ) -> list[SearchHit]:
        runtime = load_json("runtime/code_intelligence.json")
        if not pattern or len(pattern) > int(runtime["maximum_pattern_characters"]):
            raise ValueError("ripgrep pattern is empty or exceeds the configured limit")
        command = [
            "rg",
            "--json",
            "--line-number",
            "--no-config",
            "--hidden",
            "--max-filesize",
            str(runtime["rg_max_filesize"]),
        ]
        languages = load_json("code_intelligence/languages.json")
        for extension in languages["source_extensions"]:
            command.extend(("--type-add", f"plaidnox:*{extension}"))
        for filename in languages["source_filenames"]:
            command.extend(("--type-add", f"plaidnox:{filename}"))
        command.extend(("--type", "plaidnox"))
        for value in include_globs:
            command.extend(("--glob", str(value)))
        for value in exclude_globs:
            command.extend(("--glob", f"!{value}"))
        command.extend(("--", pattern, "."))
        result = subprocess.run(
            command,
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
            timeout=int(runtime["rg_timeout_seconds"]),
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError(f"ripgrep discovery failed with exit code {result.returncode}")
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
            file_ir = _fallback_ir(relative, language, content, config)
            graph.fallback_files += 1
        else:
            graph.tree_sitter_files += 1
        graph.files.append(file_ir)
        graph.symbols.extend(file_ir.symbols)
        graph.calls.extend(file_ir.calls)

    return graph


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
    symbols: list[Symbol] = []
    calls: list[Call] = []
    imports: list[str] = []

    def visit(node: Any, enclosing: str = "") -> None:
        current = enclosing
        if node.type in symbol_types:
            name_node = node.child_by_field_name("name")
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
                    )
                )
        if node.type in import_types:
            imports.append(_node_text(node, content))
        if node.type in call_types:
            function_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            callee = _node_text(function_node, content) if function_node is not None else ""
            if callee:
                calls.append(Call(current or relative, callee, relative, node.start_point[0] + 1))
        for child in node.children:
            visit(child, current)

    visit(tree.root_node)
    return FileSecurityIR(
        path=relative,
        language=language,
        content_hash=hashlib.sha256(content).hexdigest(),
        symbols=symbols,
        calls=calls,
        imports=list(dict.fromkeys(imports)),
    )


def _fallback_ir(
    relative: str,
    language: str,
    content: bytes,
    config: dict[str, Any],
) -> FileSecurityIR:
    text = content.decode("utf-8", errors="replace")
    symbols: list[Symbol] = []
    for pattern in config["fallback_symbol_patterns"]:
        compiled = re.compile(str(pattern))
        for number, line in enumerate(text.splitlines(), 1):
            match = compiled.search(line)
            if match:
                name = next((value for value in match.groups() if value), "")
                if name:
                    symbols.append(Symbol(name, relative, number, number, "fallback", name))
    if not symbols:
        name = Path(relative).stem
        symbols.append(Symbol(name, relative, 1, max(1, len(text.splitlines())), "file", name))
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
