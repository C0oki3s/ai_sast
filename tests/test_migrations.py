import hashlib

from plaidnox_sast.persistence.migrations import migration_plan


def test_postgresql_migration_plan_is_ordered_unique_and_checksummed() -> None:
    migrations = migration_plan()

    assert [item.version for item in migrations] == sorted(item.version for item in migrations)
    assert len({item.version for item in migrations}) == len(migrations)
    assert all(item.checksum == hashlib.sha256(item.sql.encode("utf-8")).hexdigest() for item in migrations)
    assert migrations[0].version == "0001_code_scanning_core"
    assert "0005_sparse_overlay_summaries" in {item.version for item in migrations}
    assert "0006_investigations" in {item.version for item in migrations}
    assert "0007_scan_finding_reports" in {item.version for item in migrations}
