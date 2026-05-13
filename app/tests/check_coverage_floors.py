#!/usr/bin/env python3
"""Enforce a per-module coverage floor on top of pytest-cov's aggregate gate.

Reads coverage.json produced by `pytest --cov-report=json:coverage.json` and
fails (exit 1) if any module's line coverage falls below the floor declared
in FLOORS below. Floors are set ~3 points below the value measured at the
time this script was added — small enough to catch genuine drift, large
enough to absorb non-deterministic noise (e.g. branches gated on import-time
fallbacks).

Raising a floor is encouraged when coverage improves. Lowering a floor
should be a deliberate, reviewable change in this file.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

FLOORS: dict[str, int] = {
    "actions.py": 80,
    "alerts.py": 90,
    "collect.py": 90,
    "db.py": 85,
    "expire.py": 88,
    "manage.py": 75,
    "servers.py": 88,
    "ssh.py": 65,
    "web.py": 85,
}


def main(report_path: str = "coverage.json") -> int:
    p = Path(report_path)
    if not p.is_file():
        print(f"FATAL: coverage report not found at {p}", file=sys.stderr)
        return 2

    data = json.loads(p.read_text())
    files = data.get("files", {})

    failures: list[str] = []
    for name, floor in FLOORS.items():
        match = next(
            (info for key, info in files.items() if Path(key).name == name),
            None,
        )
        if match is None:
            failures.append(f"  {name}: missing from coverage report")
            continue
        pct = match["summary"]["percent_covered"]
        marker = "OK  " if pct >= floor else "FAIL"
        print(f"  {marker} {name:<14} {pct:5.1f}%  (floor {floor}%)")
        if pct < floor:
            failures.append(f"  {name}: {pct:.1f}% < floor {floor}%")

    if failures:
        print("\nPer-module coverage floor breached:", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        return 1
    print("\nAll per-module floors satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "coverage.json"))
