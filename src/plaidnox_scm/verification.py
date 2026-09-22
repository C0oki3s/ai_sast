"""Independent Deep Hunt verification adapter for SCM L1 hypotheses."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Literal, Protocol

from plaidnox_sast.ai import PlaidNoxDeepHuntAgent
from plaidnox_sast.graph import build_structural_graph
from plaidnox_sast.jev import JevRouter
from plaidnox_sast.models import (
    Candidate,
    Depth,
    Evidence,
    ModelTier,
    RouteDecision,
    Severity,
)
from plaidnox_sast.validation import FindingValidator

from .assets import load_json
from .change_relevance import ReviewDepth
from .context_broker import CandidateContextExpansion, ContextBroker, SCMContextBroker
from .context_store import ApplicationContext
from .evidence import ReviewEvidence, build_review_evidence
from .l1_review import L1Candidate
from .snapshots import materialize_revision

VerificationState = Literal["verified", "rejected", "unresolved"]


@dataclass(frozen=True, slots=True)
class CandidateVerification:
    candidate_id: str
    state: VerificationState
    confidence: float
    title: str
    vulnerability_class: str
    severity: str
    message: str
    business_impact: str
    remediation: str
    reasoning: str
    attack_path: str
    security_invariant: str
    gained_capability: str
    rejection_reason: str
    evidence_locations: tuple[dict[str, object], ...]
    classification_references: tuple[dict[str, str], ...]
    evidence_gaps: tuple[str, ...]
    route: RouteDecision
    evidence: tuple[ReviewEvidence, ...] = ()
    context_expansion: CandidateContextExpansion | None = None


class CandidateVerifier(Protocol):
    def verify(
        self,
        repo_path: Path,
        head_revision: str,
        repository_name: str,
        application_context: ApplicationContext,
        candidates: tuple[L1Candidate, ...],
        minimum_depth: ReviewDepth,
    ) -> tuple[CandidateVerification, ...]: ...


class SastDeepHuntVerifier:
    """Use the Code Scanning agent as an independent verifier, never as L1 discovery."""

    def __init__(
        self,
        agent: PlaidNoxDeepHuntAgent,
        router: JevRouter | None = None,
        validator: FindingValidator | None = None,
        context_broker: ContextBroker | None = None,
    ) -> None:
        self._agent = agent
        self._router = router or JevRouter()
        self._validator = validator or FindingValidator()
        self._context_broker = context_broker or SCMContextBroker()

    def verify(
        self,
        repo_path: Path,
        head_revision: str,
        repository_name: str,
        application_context: ApplicationContext,
        candidates: tuple[L1Candidate, ...],
        minimum_depth: ReviewDepth,
    ) -> tuple[CandidateVerification, ...]:
        results: list[CandidateVerification] = []
        with materialize_revision(repo_path, head_revision) as root:
            graph = build_structural_graph(root)
            self._agent.configure_security_graph(graph)
            for hypothesis in candidates:
                candidate = _adapt_candidate(hypothesis)
                route = _at_least(self._router.classify(candidate), minimum_depth)
                expansion = self._context_broker.expand(root, graph, hypothesis, application_context)
                target = (root / hypothesis.changed_path).resolve()
                if root.resolve() not in target.parents or not target.is_file():
                    results.append(
                        _unresolved(
                            hypothesis,
                            route,
                            "Changed root-cause file is absent from the head snapshot; "
                            "baseline deletion evidence expansion is required",
                            expansion,
                        )
                    )
                    continue
                finding = self._validator.validate(repository_name, root, candidate, route)
                if finding is None:
                    results.append(
                        _unresolved(
                            hypothesis,
                            route,
                            "Candidate intake did not produce a finding",
                            expansion,
                        )
                    )
                    continue
                review = self._agent.hunt(
                    root,
                    candidate,
                    finding,
                    security_context=_security_context(application_context, expansion),
                    model_tier=route.model_tier,
                    route=route,
                )
                pending = bool(review.context_requests) or not expansion.complete
                if pending:
                    state: VerificationState = "unresolved"
                elif review.supported:
                    state = "verified"
                else:
                    state = "rejected"
                results.append(
                    CandidateVerification(
                        candidate_id=hypothesis.candidate_id,
                        state=state,
                        confidence=review.confidence,
                        title=review.title,
                        vulnerability_class=review.vulnerability_class,
                        severity=review.severity,
                        message=review.message,
                        business_impact=review.business_impact,
                        remediation=review.remediation_note,
                        reasoning=review.reasoning,
                        attack_path=review.attack_path,
                        security_invariant=review.security_invariant,
                        gained_capability=review.gained_capability,
                        rejection_reason=review.rejection_reason,
                        evidence_locations=tuple(dict(item) for item in review.evidence_locations),
                        classification_references=tuple(
                            dict(item) for item in review.classification_references
                        ),
                        evidence_gaps=(*(review.evidence_gaps or ()), *expansion.unresolved_gaps),
                        route=route,
                        evidence=build_review_evidence(
                            hypothesis,
                            expansion,
                            review.evidence_locations,
                        ),
                        context_expansion=expansion,
                    )
                )
        return tuple(results)


def _adapt_candidate(hypothesis: L1Candidate) -> Candidate:
    defaults = load_json("runtime/review.json")["provisional_adapter"]
    requested_evidence = [
        f"{item.kind}:{item.target} — {item.reason}" for item in hypothesis.requested_expansion
    ]
    return Candidate(
        rule_id=str(defaults["rule_id"]),
        title=hypothesis.suspected_broken_invariant,
        vulnerability_class=str(defaults["vulnerability_class"]),
        severity=Severity(str(defaults["severity"])),
        confidence=float(defaults["confidence"]),
        message=hypothesis.provisional_attacker_capability,
        evidence=Evidence(
            path=hypothesis.changed_path,
            start_line=hypothesis.changed_lines.start,
            end_line=hypothesis.changed_lines.end,
            source_symbol=hypothesis.changed_symbol,
        ),
        metadata={
            "category": str(defaults["category"]),
            "scm_candidate_id": hypothesis.candidate_id,
            "behavior_before": hypothesis.behavior_before,
            "behavior_after": hypothesis.behavior_after,
            "security_role": hypothesis.security_role,
            "context_facts_used": list(hypothesis.context_facts_used),
            "context_gaps": list(hypothesis.context_gaps),
            "requested_expansion": [asdict(item) for item in hypothesis.requested_expansion],
            "evidence_basis": {
                "origin": [hypothesis.provisional_attacker_capability],
                "propagation": [hypothesis.behavior_before, hypothesis.behavior_after],
                "expected_boundary": [
                    hypothesis.security_role,
                    hypothesis.suspected_broken_invariant,
                ],
                "sensitive_effect": [hypothesis.provisional_attacker_capability],
                "controls_checked": list(hypothesis.context_facts_used),
                "missing_evidence": [*hypothesis.context_gaps, *requested_evidence],
            },
            "provisional_adapter": True,
        },
    )


def _at_least(route: RouteDecision, minimum_depth: ReviewDepth) -> RouteDecision:
    requested = {
        "FAST": Depth.FAST,
        "STANDARD": Depth.STANDARD,
        "DEEP": Depth.DEEP,
    }[minimum_depth]
    rank = {Depth.FAST: 0, Depth.STANDARD: 1, Depth.DEEP: 2}
    if rank[route.depth] >= rank[requested]:
        return route
    tier = {Depth.FAST: ModelTier.FAST, Depth.STANDARD: ModelTier.STANDARD, Depth.DEEP: ModelTier.DEEP}[requested]
    return replace(
        route,
        depth=requested,
        model_tier=tier,
        reason=f"{route.reason}; raised to deterministic change-relevance minimum",
    )


def _unresolved(
    hypothesis: L1Candidate,
    route: RouteDecision,
    reason: str,
    expansion: CandidateContextExpansion | None = None,
) -> CandidateVerification:
    resolved_expansion = expansion or CandidateContextExpansion(hypothesis.candidate_id, ())
    return CandidateVerification(
        candidate_id=hypothesis.candidate_id,
        state="unresolved",
        confidence=0.0,
        title="",
        vulnerability_class="",
        severity="",
        message="",
        business_impact="",
        remediation="",
        reasoning=reason,
        attack_path="",
        security_invariant=hypothesis.suspected_broken_invariant,
        gained_capability=hypothesis.provisional_attacker_capability,
        rejection_reason="",
        evidence_locations=(),
        classification_references=(),
        evidence_gaps=(reason, *resolved_expansion.unresolved_gaps),
        route=route,
        evidence=build_review_evidence(hypothesis, resolved_expansion, []),
        context_expansion=resolved_expansion,
    )


def _security_context(
    application_context: ApplicationContext,
    expansion: CandidateContextExpansion,
) -> str:
    broker_runtime = load_json("runtime/review.json")["context_broker"]
    compact_application_context = {
        "codebase_id": application_context.codebase_id,
        "baseline_revision": application_context.baseline_revision,
        "application_type": application_context.application_type,
        "entry_points": application_context.entry_points,
        "components": application_context.components,
        "security_controls": application_context.security_controls,
        "routes": application_context.routes,
        "sensitive_effects": application_context.sensitive_effects,
        "identity_provider": application_context.identity_provider,
        "prior_finding_refs": application_context.prior_finding_refs,
        "confidence": application_context.confidence,
        "context_version": application_context.context_version,
    }
    return json.dumps(
        {
            "candidate_context_expansion": expansion.to_prompt_dict(
                int(broker_runtime["maximum_prompt_characters"])
            ),
            "application_context": compact_application_context,
        },
        default=str,
        ensure_ascii=False,
    )
