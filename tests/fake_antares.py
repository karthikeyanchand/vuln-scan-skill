#!/usr/bin/env python3
"""Test double for the Antares CLI. NOT a model: it writes a canned report so the
skill's parsing and merge logic can be tested without gated weights or a server."""
import json, sys
from pathlib import Path

args = sys.argv[1:]
out = Path(args[args.index("--output") + 1])
cwes = args[args.index("--cwe") + 1].split(",")
out.mkdir(parents=True, exist_ok=True)
report = {"target": args[1], "results": [
    {"cwe_id": c, "findings": [{"file": "app/views.py", "submission_rank": 1}] if c == "CWE-89" else []}
    for c in cwes]}
(out / "report.json").write_text(json.dumps(report))
