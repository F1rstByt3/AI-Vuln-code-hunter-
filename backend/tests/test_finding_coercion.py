"""A model can emit odd types (cwe as an int, a list where text is expected).
Persisting a finding must coerce them, not crash a 20-minute scan at the insert."""

from __future__ import annotations

from app.models import FindingSource, FindingState, Severity
from app.worker import _finding_from_dict, _text, _trunc


def test_trunc_and_text_coerce_non_strings():
    assert _trunc(89, 200) == "89"                      # the real crash: cwe as int
    assert _trunc(["A01", "A02"], 200) == "['A01', 'A02']"
    assert _trunc(None, 200) is None
    assert _trunc("x" * 250, 10) == "x" * 10
    assert _text(42) == "42" and _text(None) is None


def test_finding_from_dict_survives_weird_model_output():
    f = {
        "title": "SQLi", "severity": "high", "source": "ai", "state": "proposed",
        "cwe": 89,                       # int, not "CWE-89"
        "owasp": 1,                      # int
        "category": ["injection"],       # list
        "file_path": "db.py",
        "line_start": "42", "line_end": None,   # string line number
        "description": {"text": "x"},    # dict where str expected
        "code_snippet": 123,
        "remediation": None,
    }
    fnd = _finding_from_dict("scan-1", f)
    assert fnd.cwe == "89" and fnd.owasp == "1" and fnd.category == "['injection']"
    assert fnd.line_start == 42 and fnd.line_end is None
    assert isinstance(fnd.description, str) and isinstance(fnd.code_snippet, str)
    assert fnd.severity == Severity.high
    assert fnd.source == FindingSource.ai and fnd.state == FindingState.proposed
    assert fnd.raw is f                   # original kept verbatim for the UI
