from plaidnox_sast.routers import CandidateRouter
from plaidnox_sast.models import Candidate, Evidence, Severity
from plaidnox_sast.validation import FindingValidator


def test_candidate_intake_does_not_make_a_deterministic_vulnerability_verdict(sample_repo):
    source = sample_repo / "app.js"
    source.write_text(
        """async function signin(req, res) {
  const { idToken } = await signInUser(req.body.email, req.body.password);
  const identity = jwt.decode(idToken);
  return res.json(identity);
}
"""
    )
    candidate = Candidate(
        rule_id="plaidnox.javascript.jwt-decode-without-verification",
        title="JWT decode",
        vulnerability_class="CWE-347",
        severity=Severity.MEDIUM,
        confidence=0.7,
        message="message",
        evidence=Evidence(
            "app.js",
            3,
            3,
            "const identity = jwt.decode(idToken);",
            "signin",
            "authorization-claim-use",
            ["signin", "authentication", "authorization-claim-use"],
        ),
        metadata={"category": "authentication"},
    )
    route = CandidateRouter().classify(candidate)
    finding = FindingValidator().validate("org/repo", sample_repo, candidate, route)
    assert finding is not None
    assert finding.state.value == "discovered"
    assert finding.validator == "candidate-intake"


def test_candidate_intake_preserves_model_confidence_until_deep_hunt(sample_repo):
    source = sample_repo / "middleware.js"
    source.write_text(
        """async function authCheck(req) {
  try { return await verifier.verify(req.cookies.idToken); }
  catch (error) {
    const identity = jwt.decode(req.cookies.idToken);
    return removeAccessTokenFromDB(identity.email);
  }
}
"""
    )
    candidate = Candidate(
        rule_id="plaidnox.javascript.jwt-decode-without-verification",
        title="JWT decode",
        vulnerability_class="CWE-347",
        severity=Severity.MEDIUM,
        confidence=0.7,
        message="message",
        evidence=Evidence(
            "middleware.js",
            4,
            4,
            "const identity = jwt.decode(req.cookies.idToken);",
            "authCheck",
            "authorization-claim-use",
            ["authCheck", "authentication", "authorization-claim-use"],
        ),
        metadata={"category": "authentication"},
    )
    route = CandidateRouter().classify(candidate)
    finding = FindingValidator().validate("org/repo", sample_repo, candidate, route)
    assert finding is not None
    assert finding.confidence == 0.7
    assert finding.validator == "candidate-intake"
