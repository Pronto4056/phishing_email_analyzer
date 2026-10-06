import json
from pathlib import Path
import pytest
from phishing_analyzer.report import analyze

SAMPLES = Path(__file__).resolve().parents[1] / "src/phishing_analyzer/samples"
LABELS = json.loads((SAMPLES / "manifest.json").read_text())["samples"]


@pytest.mark.parametrize("label", LABELS, ids=[x["file"] for x in LABELS])
def test_hand_labeled_corpus(label):
    r = analyze((SAMPLES / label["file"]).read_bytes(), label["file"])["report"]
    assert [x["rule_id"] for x in r["findings"]] == label["expected_rules"]
    assert r["score"] == label["score"]
    assert r["completeness"] == label["completeness"]
