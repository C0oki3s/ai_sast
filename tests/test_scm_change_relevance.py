from __future__ import annotations

from plaidnox_scm.change_relevance import classify
from plaidnox_scm.diffing import ChangedFile, Diff, DiffHunk


def _diff(*files: ChangedFile) -> Diff:
    return Diff(base_ref="base", head_ref="head", files=tuple(files))


def _hunk(added: tuple[str, ...] = (), removed: tuple[str, ...] = ()) -> DiffHunk:
    return DiffHunk(old_start=1, old_lines=1, new_start=1, new_lines=1, header="", added_lines=added, removed_lines=removed)


def test_no_changes_is_fast_exit() -> None:
    relevance = classify(_diff())
    assert relevance.minimum_review_depth == "FAST"
    assert not relevance.docs_only and not relevance.generated_only


def test_docs_only_change_is_fast_exit() -> None:
    diff = _diff(ChangedFile(path="docs/guide.md", status="modified", old_path=None, hunks=(_hunk(added=("new text",)),)))

    relevance = classify(diff)

    assert relevance.docs_only is True
    assert relevance.security_control_changed is False
    assert relevance.minimum_review_depth == "FAST"


def test_generated_lockfile_only_change_is_fast_exit() -> None:
    diff = _diff(ChangedFile(path="package-lock.json", status="modified", old_path=None, hunks=(_hunk(added=('"x": "1"',)),)))

    relevance = classify(diff)

    assert relevance.generated_only is True
    assert relevance.minimum_review_depth == "FAST"


def test_authentication_middleware_change_is_deep() -> None:
    # The v2 plan's Fixture B: verifier.verify(token) -> jwt.decode(token)
    diff = _diff(
        ChangedFile(
            path="middleware/ValidateToken.js",
            status="modified",
            old_path=None,
            hunks=(_hunk(added=("const claims = jwt.decode(token);",), removed=("const claims = verifier.verify(token);",)),),
        )
    )

    relevance = classify(diff)

    assert relevance.security_control_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_authorization_path_change_is_deep() -> None:
    diff = _diff(ChangedFile(path="src/authz/tenant_check.py", status="modified", old_path=None, hunks=()))

    relevance = classify(diff)

    assert relevance.security_control_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_session_token_path_change_is_deep() -> None:
    diff = _diff(ChangedFile(path="src/session/token_manager.py", status="modified", old_path=None, hunks=()))

    relevance = classify(diff)

    assert relevance.security_control_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_signing_crypto_keyword_change_is_deep() -> None:
    diff = _diff(ChangedFile(path="src/crypto/signing.py", status="modified", old_path=None, hunks=()))

    relevance = classify(diff)

    assert relevance.security_control_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_security_configuration_file_change_is_deep() -> None:
    diff = _diff(ChangedFile(path="config/security.yaml", status="modified", old_path=None, hunks=()))

    relevance = classify(diff)

    assert relevance.config_changed is True
    assert relevance.security_control_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_credential_file_change_is_deep() -> None:
    diff = _diff(ChangedFile(path="deploy/service-account.json", status="added", old_path=None, hunks=()))

    relevance = classify(diff)

    assert relevance.sensitive_material_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_secret_shaped_added_line_is_sensitive_material() -> None:
    diff = _diff(
        ChangedFile(
            path="src/config.py",
            status="modified",
            old_path=None,
            hunks=(_hunk(added=("AWS_KEY = 'AKIAABCDEFGHIJKLMNOP'",)),),
        )
    )

    relevance = classify(diff)

    assert relevance.sensitive_material_changed is True
    assert relevance.minimum_review_depth == "DEEP"


def test_dependency_manifest_change_is_standard_not_deep() -> None:
    diff = _diff(ChangedFile(path="requirements.txt", status="modified", old_path=None, hunks=(_hunk(added=("flask==3.0",)),)))

    relevance = classify(diff)

    assert relevance.dependency_or_build_changed is True
    assert relevance.security_control_changed is False
    assert relevance.minimum_review_depth == "STANDARD"


def test_ordinary_runtime_source_change_is_standard() -> None:
    diff = _diff(ChangedFile(path="src/reports/export.py", status="modified", old_path=None, hunks=(_hunk(added=("x = 1",)),)))

    relevance = classify(diff)

    assert relevance.runtime_changed is True
    assert relevance.minimum_review_depth == "STANDARD"


def test_test_only_change_is_fast_exit() -> None:
    diff = _diff(ChangedFile(path="tests/test_export.py", status="modified", old_path=None, hunks=(_hunk(added=("assert True",)),)))

    relevance = classify(diff)

    assert relevance.test_only is True
    assert relevance.minimum_review_depth == "FAST"
