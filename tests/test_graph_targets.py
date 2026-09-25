from __future__ import annotations

import hashlib

import pytest

from plaidnox_sast.graph_targets import (
    GraphTargetMappingStatus,
    group_connected_graph_targets,
    map_repository_surfaces_to_graph,
)
from plaidnox_sast.graphify_adapter import CodeEdge, CodeGraphSnapshot, CodeNode


def _snapshot() -> CodeGraphSnapshot:
    source = b"line 1\nline 2\nline 3\nline 4\n"
    source_hash = hashlib.sha256(source).hexdigest()
    return CodeGraphSnapshot(
        source_hashes={"app.py": source_hash},
        nodes=(
            CodeNode("route", "app.py", 1, "GET /account", source_hash),
            CodeNode("service", "app.py", 3, "load_account", source_hash),
            CodeNode("unrelated", "app.py", 4, "health", source_hash),
        ),
        edges=(
            CodeEdge(
                "route", "service", "CALLS", "EXTRACTED", "app.py", 2, source_hash
            ),
        ),
        unresolved_edges=0,
        extractor_version="test",
    )


def _surface(name: str, start: int, end: int, source_hash: str, **extra):
    return {
        "name": name,
        "evidence_locations": [
            {
                "path": "app.py",
                "start_line": start,
                "end_line": end,
                "grounding_status": "verified_source_location",
                "source_content_hash": source_hash,
            }
        ],
        **extra,
    }


def test_maps_only_exact_hash_grounded_locations_and_keeps_stable_surface_key():
    snapshot = _snapshot()
    source_hash = snapshot.source_hashes["app.py"]
    context = {
        "entry_points": [
            _surface("account route", 1, 1, source_hash, entry_id="entry-1")
        ]
    }

    first = map_repository_surfaces_to_graph(context, snapshot)
    second = map_repository_surfaces_to_graph(context, snapshot)

    assert first.targets[0].mapping_status is GraphTargetMappingStatus.MAPPED
    assert first.targets[0].node_ids == ("route",)
    assert first.targets[0].surface_key == second.targets[0].surface_key
    assert first.graph_target_ids == ("route",)


def test_preserves_all_overlapping_nodes_as_ambiguous_instead_of_guessing():
    snapshot = _snapshot()
    context = {
        "sensitive_effects": [
            _surface(
                "account effects",
                1,
                3,
                snapshot.source_hashes["app.py"],
                effect_id="effect-1",
            )
        ]
    }

    target = map_repository_surfaces_to_graph(context, snapshot).targets[0]

    assert target.mapping_status is GraphTargetMappingStatus.AMBIGUOUS
    assert target.node_ids == ("route", "service")


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"name": "missing location"}, GraphTargetMappingStatus.NO_LOCATION),
        (
            {
                "name": "unverified",
                "evidence_locations": [
                    {"path": "app.py", "start_line": 1, "end_line": 1}
                ],
            },
            GraphTargetMappingStatus.UNVERIFIED_LOCATION,
        ),
        (
            {
                "name": "stale",
                "evidence_locations": [
                    {
                        "path": "app.py",
                        "start_line": 1,
                        "end_line": 1,
                        "grounding_status": "verified_source_location",
                        "source_content_hash": "0" * 64,
                    }
                ],
            },
            GraphTargetMappingStatus.STALE_SOURCE,
        ),
        (
            {
                "name": "outside indexed lines",
                "evidence_locations": [
                    {
                        "path": "app.py",
                        "start_line": 2,
                        "end_line": 2,
                        "grounding_status": "verified_source_location",
                        "source_content_hash": hashlib.sha256(
                            b"line 1\nline 2\nline 3\nline 4\n"
                        ).hexdigest(),
                    }
                ],
            },
            GraphTargetMappingStatus.UNMAPPED,
        ),
    ],
)
def test_reports_context_mapping_gaps_without_inventing_graph_targets(record, expected):
    inventory = map_repository_surfaces_to_graph(
        {"entry_points": [record]}, _snapshot()
    )

    assert inventory.targets[0].mapping_status is expected
    assert inventory.targets[0].node_ids == ()
    assert inventory.mapping_counts[expected.value] == 1


def test_groups_only_connected_mapped_surfaces_and_keeps_gaps_separate():
    snapshot = _snapshot()
    source_hash = snapshot.source_hashes["app.py"]
    context = {
        "entry_points": [
            _surface("account route", 1, 1, source_hash, entry_id="entry-account"),
            _surface("account lookup", 3, 3, source_hash, entry_id="entry-lookup"),
            _surface("health route", 4, 4, source_hash, entry_id="entry-health"),
            {"entry_id": "missing", "name": "unmapped surface"},
        ]
    }
    inventory = map_repository_surfaces_to_graph(context, snapshot)

    grouped = group_connected_graph_targets(inventory, snapshot)

    assert len(grouped.groups) == 2
    assert grouped.groups[0].node_ids == ("route", "service")
    assert grouped.groups[1].node_ids == ("unrelated",)
    assert grouped.unmapped_surface_keys == (inventory.targets[3].surface_key,)


def test_grouping_rejects_inventory_from_another_snapshot():
    snapshot = _snapshot()
    inventory = map_repository_surfaces_to_graph({}, snapshot)
    different = CodeGraphSnapshot({}, (), (), 0, extractor_version="different")

    with pytest.raises(ValueError, match="different source snapshot"):
        group_connected_graph_targets(inventory, different)
