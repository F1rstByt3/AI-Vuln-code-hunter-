"""Regression: Semgrep paths must be relative to the scanned tree, and legacy
paths stored as "../../../app/..." must still resolve to the real file."""

from __future__ import annotations

from app.ingestion import resolve_rel
from app.scanners.semgrep import SemgrepScanner


def test_semgrep_relative_path_resolves_inside_workdir(tmp_path):
    wf = tmp_path / "proj" / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
    result = {
        "check_id": "yaml.github-actions.mutable-tag", "path": "proj/.github/workflows/ci.yml",
        "start": {"line": 5}, "end": {"line": 5},
        "extra": {"lines": "requires login", "message": "m", "severity": "WARNING", "metadata": {}},
    }
    cand = SemgrepScanner()._to_candidate(result, str(tmp_path))
    assert cand["file_path"] == "proj/.github/workflows/ci.yml"
    assert "actions/checkout@v4" in cand["code_snippet"]
    assert "requires login" not in cand["code_snippet"]


def test_resolve_rel_repairs_legacy_paths(tmp_path):
    (tmp_path / "proj" / "src").mkdir(parents=True)
    (tmp_path / "proj" / "src" / "a.py").write_text("x = 1\n")
    assert resolve_rel(str(tmp_path), "proj/src/a.py") == "proj/src/a.py"
    assert resolve_rel(str(tmp_path), "../../../app/proj/src/a.py") == "proj/src/a.py"
    assert resolve_rel(str(tmp_path), "../../etc/passwd") is None
