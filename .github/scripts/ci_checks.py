#!/usr/bin/env python3
"""Repository health checks — the same ones CI runs.

Run them locally, unchanged:

    python .github/scripts/ci_checks.py

Every check asserts on the machine-readable `--json` output, not just the
exit code: a validator that silently stopped enforcing a rule would still
exit 0. Pure standard library, Python 3.10+.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VALIDATOR = REPO / "validator" / "acir_validator.py"
GENERATE = REPO / "tools" / "generate.py"
ECOMMERCE = REPO / "examples" / "ecommerce-v0.3.acir.json"
BOOKING = REPO / "examples" / "booking-platform-project-v0.3.acir.json"

try:
    import jsonschema  # noqa: F401
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  ok    {label}")
    else:
        print(f"  FAIL  {label}" + (f" - {detail}" if detail else ""))
        failures.append(label)


def run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, *args],
        capture_output=True, text=True, env=full_env,
        # A crashing child can emit bytes that are not valid UTF-8. Never let
        # decoding the output take down the harness itself: a failing check
        # must be reported, not raised.
        encoding="utf-8", errors="replace",
    )


def report_of(proc: subprocess.CompletedProcess) -> dict:
    """Pull the `--json` report out of a run, or {} if it never got that far."""
    _, marker, blob = proc.stdout.partition("JSON Output")
    if not marker or "{" not in blob:
        return {}
    try:
        return json.loads(blob[blob.index("{"):])
    except json.JSONDecodeError:
        return {}


def stats_of(proc: subprocess.CompletedProcess) -> dict:
    return report_of(proc).get("stats", {})


def codes_of(proc: subprocess.CompletedProcess) -> set[str]:
    return {i["code"] for i in report_of(proc).get("issues", [])}


def validate(doc: Path, *extra: str, env=None) -> subprocess.CompletedProcess:
    return run([str(VALIDATOR), str(doc), "--json", *extra], env=env)


# ── 1. The examples validate, and validate for the right reasons ───────────

print("\nExamples")

proc = validate(ECOMMERCE)
s = stats_of(proc)
check("ecommerce exits 0", proc.returncode == 0, f"exit={proc.returncode}")
check("ecommerce is a module", s.get("acir_kind") == "module", repr(s.get("acir_kind")))
check("ecommerce passes every applicable level",
      s.get("passed_levels") == s.get("total_levels") == 6,
      f"{s.get('passed_levels')}/{s.get('total_levels')}")
# The point of the whole check: without this, a run with the schema pass
# skipped still reports 6/6 and CI would go green having checked far less.
check("ecommerce ran the normative JSON-Schema" if HAS_JSONSCHEMA
      else "ecommerce reports the schema pass as skipped",
      s.get("schema_validated") is HAS_JSONSCHEMA,
      f"schema_validated={s.get('schema_validated')}")

proc = validate(BOOKING)
s = stats_of(proc)
check("booking exits 0", proc.returncode == 0, f"exit={proc.returncode}")
check("booking is a project manifest", s.get("acir_kind") == "project", repr(s.get("acir_kind")))
check("booking passes its (shorter) pipeline",
      s.get("passed_levels") == s.get("total_levels") == 2,
      f"{s.get('passed_levels')}/{s.get('total_levels')}")
check("booking reports its components", s.get("components") == 3, repr(s.get("components")))

# ── 2. Invalid documents are actually rejected ─────────────────────────────
#
# Without these, a validator that stopped enforcing anything would pass
# every check above.

print("\nRejection of invalid documents")

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    # A mutation endpoint whose unit reads $auth, but with auth removed.
    doc = json.loads(ECOMMERCE.read_text(encoding="utf-8"))
    next(e for e in doc["module"]["exposed"] if e.get("method") == "POST").pop("auth", None)
    bad_module = tmp / "bad-module.acir.json"
    bad_module.write_text(json.dumps(doc), encoding="utf-8")

    proc = validate(bad_module)
    codes = codes_of(proc)
    check("a public mutation endpoint is rejected", proc.returncode == 1, f"exit={proc.returncode}")
    check("...with AUTH_IN_PUBLIC_ROUTE", "AUTH_IN_PUBLIC_ROUTE" in codes, sorted(codes)[:4])

    # A project manifest missing a required component field.
    doc = json.loads(BOOKING.read_text(encoding="utf-8"))
    doc["project"]["components"][0].pop("name", None)
    bad_project = tmp / "bad-project.acir.json"
    bad_project.write_text(json.dumps(doc), encoding="utf-8")

    proc = validate(bad_project)
    check("a malformed project manifest is rejected",
          proc.returncode == 1 or not HAS_JSONSCHEMA,
          f"exit={proc.returncode} (needs jsonschema: {HAS_JSONSCHEMA})")

    # ── 3. Output survives a legacy console encoding ───────────────────────
    #
    # Regression test for the reports crashing with UnicodeEncodeError on a
    # cp1252 console. Forced here rather than left to the runner's locale, so
    # the check is deterministic on every OS.

    print("\nLegacy console encoding (cp1252)")

    for label, args in (("validator", [str(VALIDATOR), str(ECOMMERCE)]),
                        ("generate.py --provider mock",
                         [str(GENERATE), "--provider", "mock",
                          "--mock-responses", str(ECOMMERCE),
                          "--brief", "ci", "--out", str(tmp / "out.json")])):
        proc = run(args, env={"PYTHONIOENCODING": "cp1252"})
        check(f"{label} does not crash on cp1252",
              proc.returncode == 0 and "UnicodeEncodeError" not in proc.stderr,
              (proc.stderr.strip().splitlines() or ["exit != 0"])[-1])

    # ── 4. The generate→validate retry loop runs offline ───────────────────

    print("\nGeneration pipeline")

    proc = run([str(GENERATE), "--provider", "mock",
                "--mock-responses", str(ECOMMERCE),
                "--brief", "ci", "--out", str(tmp / "gen.json")])
    check("mock generation loop exits 0", proc.returncode == 0,
          (proc.stderr.strip().splitlines() or [""])[-1])
    check("mock generation writes a valid document",
          (tmp / "gen.json").exists() and validate(tmp / "gen.json").returncode == 0)


print(f"\njsonschema installed: {HAS_JSONSCHEMA}")
if failures:
    print(f"\n{len(failures)} check(s) failed:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("\nAll checks passed.")
