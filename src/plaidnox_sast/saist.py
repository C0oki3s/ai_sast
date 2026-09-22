from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .assets import load_json
from .graph import StructuralGraph
from .models import Candidate, Evidence, Severity


class SAISTError(RuntimeError):
    pass


class DatadogSAISTDetector:
    """Adapter for the upstream DataDog SAIST command-line scanner."""

    def __init__(
        self,
        binary: str,
        detection_model: str | None = None,
        validation_model: str | None = None,
    ) -> None:
        runtime = load_json("runtime/models.json")
        self.binary = binary
        self.detection_model = detection_model or str(runtime["saist_detection_model"])
        self.validation_model = validation_model or str(runtime["saist_validation_model"])

    def scan(self, root: Path, graph: StructuralGraph) -> list[Candidate]:
        with tempfile.TemporaryDirectory(prefix="plaidnox-saist-") as temporary:
            runtime = load_json("runtime/models.json")
            output = Path(temporary) / "results.sarif"
            command = [
                self.binary,
                "--directory",
                str(root),
                "--output",
                str(output),
                "--detection-model",
                self.detection_model,
                "--validation-model",
                self.validation_model,
                "--request-timeout-sec",
                str(runtime["saist_request_timeout_seconds"]),
            ]
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                env=os.environ.copy(),
                check=False,
                timeout=int(runtime["saist_process_timeout_seconds"]),
            )
            if result.returncode:
                raise SAISTError("DataDog SAIST scan failed")
            if not output.exists():
                raise SAISTError("DataDog SAIST did not create its SARIF output")
            return parse_saist_sarif(json.loads(output.read_text(encoding="utf-8")), root, graph)


def parse_saist_sarif(payload: dict[str, Any], root: Path, graph: StructuralGraph) -> list[Candidate]:
    candidates: list[Candidate] = []
    for run in payload.get("runs", []):
        rules = {rule.get("id", ""): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", "datadog-saist.unknown"))
            rule = rules.get(rule_id, {})
            location = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = location.get("artifactLocation", {}).get("uri", "")
            path = _relative_path(root, artifact)
            region = location.get("region", {})
            start = int(region.get("startLine", 1))
            end = int(region.get("endLine", start))
            tags = rule.get("properties", {}).get("tags", [])
            vulnerability_class = next((str(tag).upper() for tag in tags if re.fullmatch(r"CWE-\d+", str(tag).upper())), "CWE-000")
            category = _category(tags, rule_id)
            symbol = graph.symbol_at(path, start)
            title = str(rule.get("shortDescription", {}).get("text") or rule_id)
            routing = load_json("routing/saist.json")
            levels = {key: Severity(value) for key, value in routing["levels"].items()}
            candidates.append(Candidate(
                rule_id=f"datadog-saist.{rule_id}", title=title, vulnerability_class=vulnerability_class,
                severity=levels.get(
                    str(result.get("level", "warning")).lower(),
                    Severity(str(routing["default_level"])),
                ),
                confidence=float(result.get("properties", {}).get("confidence", 0.70)),
                message=str(result.get("message", {}).get("text", title)),
                evidence=Evidence(path, start, end, _redact(str(region.get("snippet", {}).get("text", ""))), symbol, rule_id, [symbol, category, rule_id]),
                metadata={"engine": "datadog-saist", "category": category, "saist_rule_id": rule_id},
            ))
    return candidates


def _relative_path(root: Path, uri: str) -> str:
    path = Path(uri.removeprefix("file://"))
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _category(tags: list[Any], rule_id: str) -> str:
    routing = load_json("routing/saist.json")
    text = " ".join(map(str, tags)).lower() + " " + rule_id.lower()
    for category in routing["category_terms"]:
        if category in text:
            return str(category)
    return str(routing["default_category"])


def _redact(value: str) -> str:
    value = re.sub(r"mongodb(?:\+srv)?://[^\s\"'`]+", "<redacted-mongodb-uri>", value, flags=re.IGNORECASE)
    return re.sub(r"\b(?:sk|rk)-[A-Za-z0-9_-]{10,}\b", "<redacted-api-key>", value)
