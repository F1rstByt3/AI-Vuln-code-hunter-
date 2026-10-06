"""Guards for ingestion result shape — the worker formats a log line from these
fields, so a renamed/typo'd attribute (e.g. analyzable→analysable) must fail a
test rather than only blowing up at scan time."""

from __future__ import annotations

from app.ingestion import FileEntry, IngestResult


def _fe(path, included):
    # FileEntry's exact fields vary; construct minimally and set what we need.
    try:
        fe = FileEntry(path=path)
    except TypeError:
        fe = FileEntry.__new__(FileEntry)
        fe.path = path
    fe.included = included
    return fe


def test_ingest_result_analyzable_count_and_worker_logline():
    r = IngestResult(workdir="/tmp/x",
                     files=[_fe("a.py", True), _fe("b.py", True), _fe("vendor/c.js", False)])
    assert r.analyzable == 2
    # Exactly the access the worker's _ingest log line makes — fails loudly if
    # the attribute is ever renamed.
    line = f"Indexed {len(r.files)} files, {r.analyzable} analysable"
    assert line == "Indexed 3 files, 2 analysable"
