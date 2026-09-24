from plaidnox_sast.fingerprint import CandidateIndex, deduplicate
from plaidnox_sast.models import Candidate, Evidence, Severity


def candidate(title, vulnerability_class, category, start, end=None, path="app.js", confidence=0.8, cwe=None):
    metadata = {"category": category}
    if cwe:
        metadata["classification_references"] = [{"identifier": cwe}]
    return Candidate(
        rule_id="plaidnox.ai",
        title=title,
        vulnerability_class=vulnerability_class,
        severity=Severity.HIGH,
        confidence=confidence,
        message=title,
        evidence=Evidence(path, start, end or start + 5, "code", category, category, []),
        metadata=metadata,
    )


def test_one_bug_named_differently_is_admitted_once():
    index = CandidateIndex()
    names = [
        ("Rate limiter is mounted after the sign-in route", "rate limiting bypass", "abuse-prevention---rate-limiting"),
        ("Middleware ordering causing rate-limit gap", "Middleware ordering", "middleware-ordering"),
        ("Signin endpoint is outside the rate limiter", "Rate limit bypass", "authentication-throttling"),
    ]
    admitted = [index.admit(candidate(t, c, k, 74, 147)) for t, c, k in names]

    assert admitted == [True, False, False]


def test_different_bug_at_a_nearby_line_is_kept():
    index = CandidateIndex()

    assert index.admit(candidate("Unverified JWT claim trust", "jwt trust", "jwt-claim-trust", 95, 103))
    assert index.admit(candidate("NoSQL operator injection in lookup", "nosql injection", "injection", 97, 99))


def test_same_text_in_another_file_or_far_away_is_kept():
    index = CandidateIndex()

    assert index.admit(candidate("Stored HTML injection", "html injection", "injection", 187, 192))
    assert index.admit(candidate("Stored HTML injection", "html injection", "injection", 187, 192, path="views/a.ejs"))
    assert index.admit(candidate("Stored HTML injection", "html injection", "injection", 400, 405))


def test_deduplicate_keeps_the_highest_confidence_report_and_counts_repeats():
    reports = [
        candidate("Reports authorization by mutable claim", "authorization", "authorization", 164, 170, confidence=0.5, cwe="CWE-639"),
        candidate("Broken authorization", "access control", "access-control", 164, 180, confidence=0.9, cwe="CWE-639"),
        candidate("Improper authorization", "authorization", "authorization", 165, 170, confidence=0.6, cwe="CWE-639"),
    ]
    kept, duplicates = deduplicate("org/repo", reports)

    assert [item.confidence for item in kept] == [0.9]
    assert duplicates == 2
    assert kept[0].metadata["duplicate_reports"] >= 1


def test_variant_index_compares_exact_locations_so_siblings_survive():
    index = CandidateIndex(nearby_lines=0)

    assert index.admit(candidate("Missing ownership check", "CWE-639", "authorization", 10, 12, cwe="CWE-639"))
    assert index.admit(candidate("Sibling missing ownership check", "CWE-639", "authorization", 14, 16, cwe="CWE-639"))
    assert not index.admit(candidate("Missing ownership check again", "CWE-639", "authorization", 10, 12, cwe="CWE-639"))


def _rooted(title, start, symbol, control, attack=""):
    item = candidate(title, "unrelated words " + title, "x" + title[:3], start, start + 2)
    item.metadata["root_cause"] = {"symbol": symbol, "security_control": control}
    item.evidence.graph_path = ["app.js", attack]
    return item


def test_declared_root_cause_merges_reports_far_apart_and_keeps_their_evidence():
    index = CandidateIndex()
    first = _rooted("Forged token accepted", 20, "authCheck", "JWT Authenticity", "forge cookie")
    far = _rooted("Signature never verified", 260, "authcheck", "jwt-authenticity", "replay token")

    assert index.admit(first) is True
    assert index.admit(far) is False
    assert first.metadata["duplicate_reports"] == 1
    assert first.metadata["supporting_evidence"] == [
        {"path": "app.js", "start_line": 260, "end_line": 262, "attack_path": "replay token"}
    ]


def test_different_declared_controls_in_one_symbol_stay_separate():
    index = CandidateIndex()
    assert index.admit(_rooted("Alpha issue", 20, "authCheck", "jwt-authenticity")) is True
    assert index.admit(_rooted("Zulu problem", 260, "authCheck", "ownership-check")) is True
