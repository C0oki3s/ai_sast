from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ai import PlaidNoxDeepHuntAgent, load_env_file
from .assets import load_json
from .config import load_local_project_config
from .context_fabric import ContextFabric, ContextFabricStore
from .graph import build_structural_graph
from .jev import JevClient, JevFrontierRouter, JevRetryRouter
from .knowledge import (
    JevKnowledgeRouter,
    KnowledgeCoordinator,
    KnowledgeStore,
    research_provider_from_environment,
)
from .models import PolicyDecision
from .persistence import (
    DatabaseConfigurationError,
    DatabaseSettings,
    PostgresContextFabricStore,
    PostgresKnowledgeStore,
)
from .persistence import session_factory as build_session_factory
from .pipeline import SastPipeline
from .reporters import write_json, write_markdown, write_repository_context, write_sarif
from .saist import DatadogSAISTDetector


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaidnox-sast", description="PlaidNox static code security pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    local = sub.add_parser("scan-local", help="scan an immutable local source snapshot")
    local.add_argument("path", type=Path)
    local.add_argument("--codebase", required=True, help="stable application codebase identity")
    local.add_argument("--revision", help="immutable source revision; defaults to a content-derived snapshot hash")
    local.add_argument("--output", type=Path, required=True)
    local.add_argument("--enforce", action="store_true")
    local.add_argument(
        "--propose-patches",
        action="store_true",
        help="propose a unified-diff fix for each verified finding and verify it against an ephemeral "
        "rescanned copy; never writes to the scanned path",
    )
    _add_ai_arguments(local)
    _add_engine_arguments(local)
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
        default=int(runtime["agent_default_max_output_tokens"]),
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="file containing LiteLLM gateway or approved provider credentials",
    )


def _add_engine_arguments(parser: argparse.ArgumentParser) -> None:
    runtime = load_json("runtime/models.json")
    parser.add_argument(
        "--jev",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="use JEV for typed scan and knowledge-routing decisions (enabled by default)",
    )
    parser.add_argument("--jev-model", default=str(runtime["jev_default_model"]))
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
    parser.add_argument(
        "--tenant-id",
        default="default",
        help="tenant scope for PostgreSQL persistence; only meaningful when "
        "PLAIDNOX_DATABASE_URL is configured",
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.env_file:
        load_env_file(args.env_file)
    deep_hunt_agent = PlaidNoxDeepHuntAgent.from_environment(args.model, args.max_output_tokens)
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
    jev_client = (
        JevClient.from_environment(args.jev_model)
        if args.jev
        else None
    )
    deep_hunt_agent.configure_capability_frontier(JevFrontierRouter(jev_client))
    deep_hunt_agent.configure_retry_route(JevRetryRouter(jev_client))
    if jev_client is not None:
        knowledge_store = (
            PostgresKnowledgeStore(persistence_session_factory, args.tenant_id)
            if persistence_session_factory is not None
            else KnowledgeStore(context_database)
        )
        deep_hunt_agent.configure_knowledge(
            KnowledgeCoordinator(
                knowledge_store,
                JevKnowledgeRouter(jev_client),
                research_provider_from_environment(
                    deep_hunt_agent.cache_telemetry,
                ),
            )
        )
    pipeline = SastPipeline(
        saist_detector=DatadogSAISTDetector(args.saist_bin) if args.saist else None,
        jev_client=jev_client,
        session_factory=persistence_session_factory,
        tenant_id=args.tenant_id,
    )
    result = pipeline.scan_snapshot(
        args.path,
        args.codebase,
        revision=args.revision,
        deep_hunt_agent=deep_hunt_agent,
        propose_patches=args.propose_patches,
    )
    _record_context_base(context_store, result, args.path)
    decision = result.policy.decision
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
                "decision": decision,
                "findings": finding_count,
                "json": str(output / "report.json"),
                "repository_context": str(output / "repository-context.json"),
                "sarif": str(output / "report.sarif"),
                "markdown": str(output / "report.md"),
            },
            indent=2,
        )
    )
    if args.enforce and decision in (PolicyDecision.BLOCK, PolicyDecision.INCOMPLETE):
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
