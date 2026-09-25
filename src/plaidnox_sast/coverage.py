"""Canonical security-obligation reconciliation across discovery regions."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

from .assets import load_json


def _normalized(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value).strip().casefold())


def obligation_identity(
    obligation_type: str,
    question: str,
    *,
    region_id: str = "",
) -> tuple[str, str]:
    """Return a stable canonical ID and configured importance for one obligation.

    Only configured semantic fields participate in cross-region identity. A
    location-only request remains region-scoped so it cannot mask another
    entry point's required work.
    """

    policy = load_json("runtime/coverage.json")
    try:
        payload = json.loads(question)
    except (json.JSONDecodeError, TypeError):
        payload = {"statement": question}
    payload = payload if isinstance(payload, dict) else {"statement": payload}

    type_name = str(obligation_type)
    fields_by_type = policy["canonical_fields_by_type"]
    selected_fields = fields_by_type.get(type_name, [])
    semantic: dict[str, list[str]] = {}
    for field_name in selected_fields:
        values = payload.get(field_name)
        if isinstance(values, list):
            normalized = sorted({_normalized(item) for item in values if _normalized(item)})
        elif values is None:
            normalized = []
        else:
            item = _normalized(values)
            normalized = [item] if item else []
        if normalized:
            semantic[str(field_name)] = normalized

    importance_by_type = policy["importance_by_type"]
    importance = str(importance_by_type.get(type_name, policy["default_importance"]))
    required_fields = policy.get("required_coverage_fields_by_type", {}).get(type_name, [])
    if any(payload.get(field_name) for field_name in required_fields):
        importance = "REQUIRED"

    if semantic:
        identity_payload: dict[str, Any] = {"type": type_name, "requirements": semantic}
    else:
        identity_payload = {
            "type": type_name,
            "region_id": region_id,
            "question": _normalized(question),
        }
    canonical_id = hashlib.sha256(
        json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return canonical_id, importance


def reconcile_obligations(observations: list[dict[str, Any]]) -> dict[str, int]:
    """Merge per-region dispositions and count unresolved canonical work.

    A canonical obligation is satisfied when any region has a grounded
    terminal result. Candidate validity remains governed by candidate grounding
    and Deep Hunt verification; this function only reconciles coverage status.
    """

    policy = load_json("runtime/coverage.json")
    resolved_statuses = set(policy["resolved_statuses"])
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        obligation = dict(observation.get("obligation") or {})
        question = str(obligation.get("question", ""))
        canonical_id = str(obligation.get("canonical_id", ""))
        importance = str(obligation.get("importance", ""))
        if not canonical_id:
            canonical_id, derived_importance = obligation_identity(
                str(obligation.get("type", "")),
                question,
                region_id=str(observation.get("region_id", "")),
            )
            importance = importance or derived_importance
        coverage_scope = str(observation.get("coverage_scope", ""))
        group_id = f"{canonical_id}:{coverage_scope}" if coverage_scope else canonical_id
        groups[group_id].append(
            {
                "status": str(observation.get("status", "UNRESOLVED")),
                "importance": importance or policy["default_importance"],
            }
        )

    unresolved_required = 0
    unresolved_supporting = 0
    reconciled_by_sibling = 0
    required_total = 0
    for records in groups.values():
        is_required = any(record["importance"] == "REQUIRED" for record in records)
        required_total += int(is_required)
        has_resolved = any(record["status"] in resolved_statuses for record in records)
        has_unresolved = any(record["status"] == "UNRESOLVED" for record in records)
        has_pending = any(record["status"] == "NEEDS_CONTEXT" for record in records)
        if has_resolved:
            reconciled_by_sibling += int(has_unresolved or has_pending)
            continue
        if not (has_unresolved or has_pending):
            continue
        if is_required:
            unresolved_required += 1
        else:
            unresolved_supporting += 1

    return {
        "canonical_obligations_total": len(groups),
        "canonical_required_obligations": required_total,
        "canonical_required_unresolved": unresolved_required,
        "canonical_supporting_unresolved": unresolved_supporting,
        "obligations_reconciled_by_sibling": reconciled_by_sibling,
    }


def reconcile_workset_batches(
    observations: list[dict[str, Any]],
    planned_batches: list[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Reduce batch-local answers only after every planned workset batch is accounted for.

    A clean answer from one batch cannot complete a required obligation assigned
    to another batch. Multi-batch work is scoped to its workset so an unrelated
    sibling region cannot hide an incomplete batch.
    """

    planned: dict[tuple[str, str, str], dict[str, Any]] = {}
    region_keys: dict[str, tuple[str, str]] = {}
    workset_indices: dict[tuple[str, str], set[int]] = defaultdict(set)
    workset_counts: dict[tuple[str, str], int] = {}
    for batch in planned_batches:
        workset = batch.get("security_workset") or {}
        if int(workset.get("batch_count", 1)) <= 1:
            continue
        region_id = str(batch["region_id"])
        scope = (str(workset["workset_id"]), str(workset["evidence_hash"]))
        region_keys[region_id] = scope
        workset_indices[scope].add(int(workset["batch_index"]))
        workset_counts[scope] = int(workset["batch_count"])
        for obligation in batch.get("obligations", []):
            canonical_id = str(obligation["canonical_id"])
            key = (*scope, canonical_id)
            entry = planned.setdefault(
                key,
                {"obligation": dict(obligation), "regions": set(), "statuses": {}},
            )
            entry["regions"].add(region_id)

    passthrough: list[dict[str, Any]] = []
    for observation in observations:
        region_id = str(observation.get("region_id", ""))
        scope = region_keys.get(region_id)
        if scope is None:
            passthrough.append(observation)
            continue
        canonical_id = str((observation.get("obligation") or {}).get("canonical_id", ""))
        entry = planned.get((*scope, canonical_id))
        if entry is not None:
            entry["statuses"].setdefault(region_id, []).append(str(observation.get("status", "UNRESOLVED")))

    unresolved = 0
    missing = 0
    for (workset_id, evidence_hash, _canonical_id), entry in planned.items():
        statuses_by_region = entry["statuses"]
        expected = entry["regions"]
        missing += len(expected - statuses_by_region.keys())
        all_statuses = [status for statuses in statuses_by_region.values() for status in statuses]
        complete = expected == statuses_by_region.keys() and all(
            len(statuses_by_region[region_id]) == 1
            and statuses_by_region[region_id][0] in {"NO_ISSUE", "NOT_APPLICABLE", "CANDIDATE_FOUND"}
            for region_id in expected
        )
        if not complete:
            unresolved += 1
        status = (
            "UNRESOLVED" if not complete
            else "CANDIDATE_FOUND" if "CANDIDATE_FOUND" in all_statuses
            else "NO_ISSUE" if "NO_ISSUE" in all_statuses
            else "NOT_APPLICABLE"
        )
        passthrough.append(
            {
                "region_id": workset_id,
                "coverage_scope": f"{workset_id}:{evidence_hash}",
                "obligation": entry["obligation"],
                "status": status,
            }
        )
    absent_batches = 0
    for (workset_id, evidence_hash), indices in workset_indices.items():
        absent = set(range(workset_counts[(workset_id, evidence_hash)])) - indices
        absent_batches += len(absent)
        if absent:
            passthrough.append(
                {
                    "region_id": workset_id,
                    "coverage_scope": f"{workset_id}:{evidence_hash}",
                    "obligation": {
                        "canonical_id": f"workset-batches:{workset_id}:{evidence_hash}",
                        "importance": "REQUIRED",
                    },
                    "status": "UNRESOLVED",
                }
            )
    return passthrough, {
        "workset_batch_obligations_reconciled": len(planned),
        "workset_batch_obligations_unresolved": unresolved,
        "workset_batch_observations_missing": missing,
        "workset_batches_missing": absent_batches,
    }
