#!/usr/bin/env python3
"""Compile a document, install the result, and run the tests it ships with.

    python compilers/e2e_check.py            # verify
    python compilers/e2e_check.py --update   # re-pin after an intended change

`determinism_check.py` proves the compiler produces the same bytes every time.
It says nothing about whether those bytes work. This runs the generated
project's own test suite — the compiler emits `tests/` on every compilation,
and until this existed nobody had ever executed it.

Needs network and about a minute: it creates a virtualenv and installs the
generated project's dependencies (FastAPI, SQLAlchemy, pytest…). The tests
themselves run against SQLite, so no database server is required.

## Why this pins a result instead of requiring green

The generated suite does not currently pass. The failures are real defects in
the compiler, not flaky tests, and they are listed in `E2E_EXPECTED.json` with
the issue tracking each one. Pinning them means:

  - a *new* failure fails this check, so regressions are caught;
  - a known failure that starts passing also fails it, so a fix cannot land
    without updating the pin and closing the issue.

The alternative — leaving the suite unexecuted until it is perfect — is how it
came to ship broken in the first place.

Standard library only, Python 3.10+.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMPILER = REPO / "compilers" / "acir_compiler_fastapi.py"
EXPECTED = REPO / "compilers" / "E2E_EXPECTED.json"
DOCUMENT = "examples/ecommerce-v0.3.acir.json"

SUMMARY = re.compile(r"(?:(\d+) failed)?,?\s*(\d+) passed")
FAILED_TEST = re.compile(r"^FAILED (\S+)", re.MULTILINE)
ERROR_TEST = re.compile(r"^ERROR (\S+)", re.MULTILINE)


def run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true",
                    help="Re-pin E2E_EXPECTED.json. Only alongside a fix, and close the issue.")
    ap.add_argument("--keep", action="store_true",
                    help="Leave the generated project on disk for inspection.")
    args = ap.parse_args()

    work = Path(tempfile.mkdtemp(prefix="acir-e2e-"))
    project = work / "project"
    try:
        print(f"compiling {DOCUMENT}")
        proc = run([sys.executable, str(COMPILER), str(REPO / DOCUMENT), str(project)])
        if proc.returncode != 0:
            print(proc.stderr.strip()[-800:])
            return 1

        print("creating a virtualenv and installing the generated requirements")
        venv = project / ".venv"
        if run([sys.executable, "-m", "venv", str(venv)]).returncode != 0:
            print("  could not create the virtualenv")
            return 1
        python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")

        install = run([str(python), "-m", "pip", "install", "-q",
                       "--disable-pip-version-check", "-r", str(project / "requirements.txt")])
        if install.returncode != 0:
            print("  install failed:")
            print("  " + (install.stderr.strip().splitlines() or ["?"])[-1])
            return 1

        print("running the generated test suite\n")
        pytest = run([str(python), "-m", "pytest", "-q", "--no-header"], cwd=project)
        output = pytest.stdout + pytest.stderr

        failing = sorted(set(FAILED_TEST.findall(output)) | set(ERROR_TEST.findall(output)))
        match = SUMMARY.search(output)
        passed = int(match.group(2)) if match else 0

        for line in output.splitlines():
            if line.startswith(("FAILED", "ERROR")) or " passed" in line or " failed" in line:
                print(f"  {line.strip()[:150]}")

        result = {"passed": passed, "failing": failing}

        if args.update:
            previous = json.loads(EXPECTED.read_text(encoding="utf-8")) if EXPECTED.exists() else {}
            result["known_failures"] = previous.get("known_failures", {})
            EXPECTED.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print(f"\n{EXPECTED.name} updated — document each failure and link its issue.")
            return 0

        if not EXPECTED.exists():
            print(f"\nno {EXPECTED.name}; run with --update")
            return 1

        pinned = json.loads(EXPECTED.read_text(encoding="utf-8"))
        problems = []

        new_failures = set(failing) - set(pinned["failing"])
        if new_failures:
            problems.append(f"new failure(s): {sorted(new_failures)}")

        now_passing = set(pinned["failing"]) - set(failing)
        if now_passing:
            problems.append(
                f"these were expected to fail and now pass: {sorted(now_passing)} — "
                f"re-pin with --update and close the issue")

        if passed < pinned["passed"]:
            problems.append(f"fewer tests pass than pinned: {passed} < {pinned['passed']}")

        if problems:
            print("\nFAIL")
            for p in problems:
                print(f"  - {p}")
            return 1

        print(f"\n{passed} passed, {len(failing)} known failure(s) — as pinned.")
        for test in failing:
            note = pinned.get("known_failures", {}).get(test, "undocumented")
            print(f"  {test}\n      {note}")
        return 0
    finally:
        if args.keep:
            print(f"\nkept: {project}")
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
