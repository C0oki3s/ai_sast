"""plaidnox-scm command-line entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from plaidnox_sast.llm import LiteLLMConfigurationError
from plaidnox_sast.persistence import DatabaseConfigurationError, DatabaseSettings

from .models import Base
from .production import dependencies_from_environment
from .review import ReviewResult, review_pull_request


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaidnox-scm", description="PlaidNox SCM/PR security review")
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="review a base..head diff in a local git checkout")
    review.add_argument("--repo", required=True, type=Path)
    review.add_argument("--base", required=True)
    review.add_argument("--head", required=True)
    review.add_argument("--codebase", required=True, help="stable application codebase identity")
    review.add_argument("--tenant", default="default")
    review.add_argument(
        "--context-store",
        type=Path,
        help="transitional local-only SQLite ApplicationContext cache path; ignored when "
        "PLAIDNOX_DATABASE_URL is configured",
    )
    return parser


def _result_to_json(result: ReviewResult) -> dict[str, Any]:
    context = result.application_context
    return {
        "outcome": result.outcome,
        "detail": result.detail,
        "candidate_count": result.candidate_count,
        "ai_review_invoked": result.ai_review_invoked,
        "coverage_complete": result.coverage_complete,
        "coverage_gaps": list(result.coverage_gaps),
        "counters": asdict(result.counters),
        "candidates": [asdict(item) for item in result.candidates],
        "verifications": [asdict(item) for item in result.verifications],
        "baseline_classifications": [asdict(item) for item in result.baseline_classifications],
        "relevance": {
            "runtime_changed": result.relevance.runtime_changed,
            "security_control_changed": result.relevance.security_control_changed,
            "config_changed": result.relevance.config_changed,
            "sensitive_material_changed": result.relevance.sensitive_material_changed,
            "dependency_or_build_changed": result.relevance.dependency_or_build_changed,
            "test_only": result.relevance.test_only,
            "docs_only": result.relevance.docs_only,
            "generated_only": result.relevance.generated_only,
            "changed_files": list(result.relevance.changed_files),
            "changed_symbols": list(result.relevance.changed_symbols),
            "minimum_review_depth": result.relevance.minimum_review_depth,
        },
        "application_context": (
            None
            if context is None
            else {
                "codebase_id": context.codebase_id,
                "baseline_revision": context.baseline_revision,
                "source_tree_hash": context.source_tree_hash,
                "builder_version": context.builder_version,
                "application_type": context.application_type,
                "confidence": context.confidence,
                "context_version": context.context_version,
                "computed_at": context.computed_at.isoformat(),
            }
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command != "review":
        return 1

    try:
        settings = DatabaseSettings.from_environment()
        engine = settings.create_engine()
        transitional_local_store = False
    except DatabaseConfigurationError:
        context_path = (args.context_store or Path("plaidnox-scm-context.sqlite")).resolve()
        engine = create_engine(f"sqlite+pysqlite:///{context_path}")
        transitional_local_store = True

    if transitional_local_store:
        Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)

    result = review_pull_request(args.repo, args.base, args.head, args.codebase, args.tenant, factory)
    if result.outcome == "configuration_required":
        try:
            dependencies = dependencies_from_environment()
        except LiteLLMConfigurationError:
            dependencies = None
        if dependencies is not None:
            result = review_pull_request(
                args.repo,
                args.base,
                args.head,
                args.codebase,
                args.tenant,
                factory,
                context_builder=dependencies.context_builder,
                l1_reviewer=dependencies.l1_reviewer,
                candidate_verifier=dependencies.candidate_verifier,
            )
    json.dump(_result_to_json(result), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if result.outcome in {"pass_fast_exit", "pass_no_verified_finding"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
