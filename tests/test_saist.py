from plaidnox_sast.graph import StructuralGraph, Symbol
from plaidnox_sast.models import Severity
from plaidnox_sast.saist import parse_saist_sarif


def test_saist_sarif_is_converted_to_redacted_candidate(tmp_path):
    source = tmp_path / "app.js"
    source.write_text("const uri = 'mongodb+srv://user:pass@host/db';\n")
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "javascript.ssrf",
                                "shortDescription": {"text": "Server-side request forgery"},
                                "properties": {"tags": ["CWE-918", "ssrf"]},
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "javascript.ssrf",
                        "level": "error",
                        "message": {"text": "Request reaches an outbound URL"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(source)},
                                    "region": {"startLine": 1, "snippet": {"text": source.read_text()}},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    graph = StructuralGraph(symbols=[Symbol("handler", "app.js", 1)])
    candidates = parse_saist_sarif(payload, tmp_path, graph)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.rule_id == "datadog-saist.javascript.ssrf"
    assert candidate.severity is Severity.HIGH
    assert candidate.vulnerability_class == "CWE-918"
    assert candidate.metadata["engine"] == "datadog-saist"
    assert "mongodb+srv://" not in candidate.evidence.snippet
