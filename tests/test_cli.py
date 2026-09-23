from pathlib import Path

from plaidnox_sast.cli import _parser


def test_scan_local_parser_declares_tenant_once() -> None:
    args = _parser().parse_args(
        [
            "scan-local",
            "/snapshot",
            "--codebase",
            "owner/service",
            "--output",
            "/output",
            "--tenant-id",
            "tenant-a",
        ]
    )

    assert args.path == Path("/snapshot")
    assert args.tenant_id == "tenant-a"


def test_phase_five_and_six_commands_are_parseable() -> None:
    parser = _parser()

    acceptance = parser.parse_args(
        ["evaluate-acceptance", "acceptance/manifest.json", "--output", "acceptance/result.json"]
    )
    migrate = parser.parse_args(["migrate"])
    worker = parser.parse_args(["worker-once", "--tenant-id", "tenant-a", "--worker-id", "worker-a"])

    assert acceptance.command == "evaluate-acceptance"
    assert migrate.command == "migrate"
    assert worker.command == "worker-once"
