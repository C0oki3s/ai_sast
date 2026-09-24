from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path

from .acceptance import evaluate_acceptance_manifest, write_acceptance_result
from .ai import load_env_file
from .optimized_ai import OptimizedPlaidNoxDeepHuntAgent
from .asset_bundle import (
    create_asset_bundle,
    load_asset_bundle,
    verify_asset_bundle,
    verify_configured_asset_bundle,
    write_asset_bundle,
)
from .assets import load_json
from .config import load_local_project_config
from .context_fabric import ContextFabric, ContextFabricStore
from .environment import load_mounted_secrets
from .graph import build_structural_graph
from .routers import FrontierRouter, ModelExecutionRouter, RetryRouter
from .knowledge import (
    KnowledgeCoordinator,
    KnowledgeStore,
    research_provider_from_environment,
)
from .observability import ScanTelemetry
from .persistence import (
    DatabaseConfigurationError,
    DatabaseSettings,
    PostgresContextFabricStore,
    PostgresKnowledgeStore,
    apply_migrations,
    snapshot_tree_hash,
    stable_id,
    unit_of_work,
)
from .persistence import session_factory as build_session_factory
from .pipeline import SastPipeline
from .reporters import write_json, write_markdown, write_repository_context, write_sarif
from .saist import DatadogSAISTDetector
from .worker import LocalScanExecutor, ScanWorker, WorkerPaths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaidnox-sast", description="PlaidNox static code security pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    local = sub.add_parser("scan-local", help="scan an immutable local source snapshot")
    local.add_argument("path", type=Path)
    local.add_argument("--codebase", required=True, help="stable application codebase identity")
    local.add_argument("--revision", help="immutable source revision; defaults to a content-derived snapshot hash")
    local.add_argument("--output", type=Path, required=True)
    local.add_argument(
        "--checkpoint",
        type=Path,
        help=(
            "durable resume store (default: OUTPUT/scan-checkpoint.sqlite); completed work and "
            "LLM responses are replayed, while the last pending model operation is retried"
        ),
    )
    local.add_argument("--no-checkpoint", action="store_true", help="disable durable checkpointing")
    local.add_argument("--enforce", action="store_true")
    local.add_argument(
        "--propose-patches",
        action="store_true",
        help="propose a unified-diff fix for each verified finding and verify it against an ephemeral "
        "rescanned copy; never writes to the scanned path",
    )
    _add_ai_arguments(local)
    _add_engine_arguments(local)

    acceptance = sub.add_parser("evaluate-acceptance", help="evaluate immutable scan reports against expectations")
    acceptance.add_argument("manifest", type=Path)
    acceptance.add_argument("--output", type=Path, required=True)

    migrate = sub.add_parser("migrate", help="apply ordered Code Scanning PostgreSQL migrations")
    migrate.add_argument("--env-file", type=Path)

    create_bundle = sub.add_parser("create-asset-bundle", help="sign the installed policy/runtime assets")
    create_bundle.add_argument("--bundle-version", required=True)
    create_bundle.add_argument("--key-id", required=True)
    create_bundle.add_argument("--validity-days", type=int, default=30)
    create_bundle.add_argument("--output", type=Path, required=True)
    create_bundle.add_argument("--env-file", type=Path)

    verify_bundle = sub.add_parser("verify-asset-bundle", help="verify a signed policy/runtime asset bundle")
    verify_bundle.add_argument("bundle", type=Path)
    verify_bundle.add_argument("--env-file", type=Path)

    enqueue = sub.add_parser("enqueue-local", help="enqueue an immutable local snapshot for a worker")
    enqueue.add_argument("path", type=Path)
    enqueue.add_argument("--codebase", required=True)
    enqueue.add_argument("--revision", required=True)
    enqueue.add_argument("--request-key", required=True)
    enqueue.add_argument("--output", type=Path, required=True)
    enqueue.add_argument("--tenant-id", required=True)
    enqueue.add_argument("--priority", type=int, default=100)
    enqueue.add_argument("--env-file", type=Path)

    for name, help_text in (
        ("worker-once", "lease and execute at most one queued scan job"),
        ("worker", "continuously lease and execute queued scan jobs"),
    ):
        worker = sub.add_parser(name, help=help_text)
        worker.add_argument("--tenant-id", required=True)
        worker.add_argument("--worker-id")
        worker.add_argument("--env-file", type=Path)
    return parser


def _add_ai_arguments(parser: argparse.ArgumentParser) -> None:
    runtime = load_json("runtime/models.json")
    parser.add_argument(
        "--model",
        default=str(runtime["agent_default_model"]),
        help="model resolved by the PlaidNox model gateway",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=None,
        help=(
            "cap each AI response's output tokens; unset uses the production limit from "
            "runtime/models.json"
        ),
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="file containing LiteLLM gateway or approved provider credentials",
    )


def _add_engine_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--saist", action="store_true", help="run the upstream DataDog SAIST scanner")
    parser.add_argument("--saist-bin", help="path to the datadog-saist binary")
    parser.add_argument(
        "--context-store",
        type=Path,
        help="explicit local-only SQLite context cache path",
    )
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="tenant scope for PostgreSQL persistence; only meaningful when "
        "PLAIDNOX_DATABASE_URL is configured",
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "evaluate-acceptance":
        result = evaluate_acceptance_manifest(args.manifest)
        write_acceptance_result(result, args.output)
        print(json.dumps(result.to_dict(), indent=2))
        return 0 if result.passed else 2
    if getattr(args, "env_file", None):
        load_env_file(args.env_file)
    load_mounted_secrets()
    if args.command == "migrate":
        settings = DatabaseSettings.from_environment()
        applied = apply_migrations(settings.create_engine())
        print(json.dumps({"database": settings.redacted_url, "applied": applied}, indent=2))
        return 0
    if args.command == "create-asset-bundle":
        policy = load_json("runtime/production_controls.json")["asset_bundle"]
        key = os.environ.get(str(policy["key_environment_variable"]), "")
        bundle = create_asset_bundle(
            args.bundle_version,
            args.key_id,
            key,
            validity_days=args.validity_days,
        )
        write_asset_bundle(bundle, args.output)
        print(json.dumps({"bundle_version": args.bundle_version, "output": str(args.output)}, indent=2))
        return 0
    if args.command == "verify-asset-bundle":
        policy = load_json("runtime/production_controls.json")["asset_bundle"]
        key = os.environ.get(str(policy["key_environment_variable"]), "")
        verified = verify_asset_bundle(load_asset_bundle(args.bundle), key)
        print(json.dumps({"bundle_version": verified.bundle_version, "assets": verified.asset_count}, indent=2))
        return 0
    if args.command == "enqueue-local":
        return _enqueue_local(args)
    if args.command in {"worker-once", "worker"}:
        return _run_worker(args, continuous=args.command == "worker")
    return _run_scan_local(args)


def _enqueue_local(args: argparse.Namespace) -> int:
    verify_configured_asset_bundle()
    settings = DatabaseSettings.from_environment()
    factory = build_session_factory(settings)
    snapshot = args.path.resolve()
    if not snapshot.is_dir():
        raise SystemExit("snapshot path must be an existing directory")
    output = args.output.resolve()
    config = load_local_project_config(snapshot)
    tree_hash = snapshot_tree_hash(
        build_structural_graph(snapshot, exclude=config.exclude, max_file_bytes=config.max_file_bytes)
    )
    with unit_of_work(factory, args.tenant_id) as repository:
        job = repository.enqueue_scan_job(
            args.request_key,
            args.codebase,
            args.revision,
            snapshot.as_uri(),
            output.as_uri(),
            job_data={"snapshot_tree_hash": tree_hash},
            priority=args.priority,
        )
        repository.append_audit_event(
            stable_id("audit", job.job_id, "queued"),
            "scan_job_queued",
            "operator",
            "cli",
            "scan_job",
            job.job_id,
            "success",
            {"codebase": args.codebase, "revision": args.revision},
        )
    print(json.dumps({"job_id": job.job_id, "state": job.state}, indent=2))
    return 0


def _run_worker(args: argparse.Namespace, *, continuous: bool) -> int:
    verify_configured_asset_bundle()
    settings = DatabaseSettings.from_environment()
    factory = build_session_factory(settings)
    runtime = load_json("runtime/production_controls.json")["worker"]
    worker_id = args.worker_id or os.environ.get(str(runtime["worker_id_environment_variable"]), "")
    worker = ScanWorker(
        factory,
        args.tenant_id,
        worker_id,
        LocalScanExecutor(
            WorkerPaths.from_environment(),
            timeout_seconds=int(runtime["scan_timeout_seconds"]),
        ),
        lease_seconds=int(runtime["lease_seconds"]),
        heartbeat_seconds=int(runtime["heartbeat_seconds"]),
    )
    if not continuous:
        job = worker.run_once()
        print(json.dumps({"processed": job.job_id if job else None}, indent=2))
        return 0
    stop = threading.Event()

    def request_stop(_signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    idle_seconds = float(runtime["idle_poll_seconds"])
    while not stop.is_set():
        try:
            job = worker.run_once()
        except Exception as exc:  # worker already persisted a redacted failure audit
            print(json.dumps({"event": "scan_job_failed", "error_type": type(exc).__name__}), file=sys.stderr)
            # Back off: a persistent failure (e.g. database down) must not hot-loop.
            stop.wait(idle_seconds)
            continue
        if job is None:
            stop.wait(idle_seconds)
    return 0


def _run_scan_local(args: argparse.Namespace) -> int:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    verify_configured_asset_bundle()
    deep_hunt_agent = OptimizedPlaidNoxDeepHuntAgent.from_environment(args.model, args.max_output_tokens)
    deep_hunt_agent.set_event_sink(lambda event: print(json.dumps(event, sort_keys=True), file=sys.stderr, flush=True))
    if args.saist and not args.saist_bin:
        raise SystemExit("--saist requires --saist-bin pointing to the upstream datadog-saist binary")

    try:
        database_settings = DatabaseSettings.from_environment()
        persistence_session_factory = build_session_factory(database_settings)
    except DatabaseConfigurationError:
        persistence_session_factory = None

    # A PostgreSQL context/knowledge backend replaces the transitional SQLite
    # one whenever PLAIDNOX_DATABASE_URL is configured; --context-store then
    # only matters as a fallback path.
    context_database = args.context_store or output / "context-fabric.sqlite"
    context_store = (
        PostgresContextFabricStore(persistence_session_factory, args.tenant_id)
        if persistence_session_factory is not None
        else ContextFabricStore(context_database)
    )
    deep_hunt_agent.configure_context_fabric(context_store)
    deep_hunt_agent.configure_capability_frontier(FrontierRouter())
    deep_hunt_agent.configure_retry_route(RetryRouter())
    deep_hunt_agent.configure_model_execution_route(ModelExecutionRouter())
    knowledge_store = (
        PostgresKnowledgeStore(persistence_session_factory, args.tenant_id)
        if persistence_session_factory is not None
        else KnowledgeStore(context_database)
    )
    deep_hunt_agent.configure_knowledge(
        KnowledgeCoordinator(
            knowledge_store,
            research_provider_from_environment(
                deep_hunt_agent.model_budget,
            ),
        )
    )
    pipeline = SastPipeline(
        saist_detector=DatadogSAISTDetector(args.saist_bin) if args.saist else None,
        session_factory=persistence_session_factory,
        tenant_id=args.tenant_id,
        checkpoint_path=None if args.no_checkpoint else (args.checkpoint or output / "scan-checkpoint.sqlite"),
    )
    telemetry = ScanTelemetry.from_environment()
    with telemetry.scan(args.codebase, args.revision):
        result = pipeline.scan_snapshot(
            args.path,
            args.codebase,
            revision=args.revision,
            deep_hunt_agent=deep_hunt_agent,
            propose_patches=args.propose_patches,
        )
        telemetry.record_result(result)
    _record_context_base(context_store, result, args.path)
    status = result.scan_status
    finding_count = len(result.findings)
    write_json(result, output / "report.json")
    write_repository_context(result, output / "repository-context.json")
    write_sarif(result, output / "report.sarif")
    write_markdown(result, output / "report.md")
    print(
        json.dumps(
            {
                "codebase": result.codebase,
                "revision": result.revision,
                "scan_status": status.value,
                "findings": finding_count,
                "json": str(output / "report.json"),
                "repository_context": str(output / "repository-context.json"),
                "sarif": str(output / "report.sarif"),
                "markdown": str(output / "report.md"),
            },
            indent=2,
        )
    )
    if args.enforce and status.value == "UNSUCCESSFUL":
        return 2
    return 0


def _record_context_base(context_store: ContextFabric | None, result, root: Path) -> None:
    """Record the reusable snapshot through the configured persistence adapter."""
    if context_store is None:
        return
    config = load_local_project_config(root)
    graph = build_structural_graph(
        root,
        exclude=config.exclude,
        max_file_bytes=config.max_file_bytes,
    )
    context = context_store.create_base(result.codebase, result.revision, root, graph)
    result.repository_context["context_fabric"] = {
        "context_id": context.context_id,
        "revision": context.commit,
        "symbol_count": context.symbol_count,
        "reused": context.reused,
    }


if __name__ == "__main__":
    raise SystemExit(main())
