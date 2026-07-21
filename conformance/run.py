#!/usr/bin/env python3
"""Run the conformance corpus against an ACIR validator.

    python conformance/run.py                    # the reference validator
    python conformance/run.py --validator "node my-validator.js"

The corpus itself is plain JSON (`manifest.json` + `cases/`) and carries no
Python. This file is one reference harness for it; porting it to another
language means reimplementing `report_for()` and nothing else.

Two things are checked for every case:

  1. the verdict and the required issues match `expect` in the manifest;
  2. the verdict does not depend on whether the optional `jsonschema`
     dependency is installed — run this twice, with and without it, and the
     results must be identical.

Standard library only, Python 3.10+.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REFERENCE = [sys.executable, str(ROOT.parent / "validator" / "acir_validator.py")]


def report_for(command: list[str], document: Path) -> dict:
    """Run one validator over one document and return its JSON report.

    The only implementation-specific part of this harness. A conforming
    validator must be invocable as `<command> <document> --json` and print a
    report containing `valid` and `issues[]`, each issue carrying `code`,
    `level` and `severity`.
    """
    proc = subprocess.run(
        [*command, str(document), "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    _, marker, blob = proc.stdout.partition("JSON Output")
    if not marker or "{" not in blob:
        raise SystemExit(
            f"{document.name}: no JSON report on stdout.\n"
            f"  exit={proc.returncode}\n  {proc.stderr.strip()[:400]}"
        )
    return json.loads(blob[blob.index("{"):])


def missing_issues(expected: list[dict], reported: list[dict]) -> list[dict]:
    """Expected issues absent from the report.

    Subset semantics, deliberately: an implementation may report *more* than
    the corpus requires (extra advisories, finer-grained findings). It may
    never report less, and it may never disagree on the verdict.
    """
    def present(want: dict) -> bool:
        return any(
            got.get("code") == want["code"]
            and got.get("level") == want["level"]
            and got.get("severity") == want["severity"]
            for got in reported
        )
    return [w for w in expected if not present(w)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--validator", default=None,
                    help="Command to invoke (default: the reference validator).")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="List every case, not just failures.")
    args = ap.parse_args()

    command = shlex.split(args.validator) if args.validator else REFERENCE
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))

    failures: list[str] = []
    for case in manifest["cases"]:
        cid = case["id"]
        report = report_for(command, ROOT / case["document"])
        expect = case["expect"]
        problems = []

        if report.get("valid") is not expect["valid"]:
            problems.append(
                f"verdict: expected valid={expect['valid']}, got {report.get('valid')}")

        for want in missing_issues(expect["issues"], report.get("issues", [])):
            problems.append(
                f"missing {want['severity']} {want['code']} at level {want['level']}")

        if problems:
            failures.append(cid)
            print(f"  FAIL  {cid}")
            for p in problems:
                print(f"          {p}")
            got = sorted({f"{i.get('severity')}:{i.get('code')}"
                          for i in report.get("issues", [])})
            print(f"          reported: {got or 'nothing'}")
        elif args.verbose:
            print(f"  ok    {cid}")

    total = len(manifest["cases"])
    schema_ran = report.get("stats", {}).get("schema_validated")
    print(f"\n{total - len(failures)}/{total} cases passed "
          f"(normative JSON-Schema pass: "
          f"{'applied' if schema_ran else 'skipped - install jsonschema'})")

    if failures:
        print("\nRun again with --verbose for the full list.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
