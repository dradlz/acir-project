#!/usr/bin/env python3
"""Prove that compiling the same document twice yields the same bytes.

    python compilers/determinism_check.py            # verify
    python compilers/determinism_check.py --update   # re-pin after an
                                                     # intentional change

Determinism is the guarantee this project exists to make, and it is the one
claim a reader cannot check by inspection. This makes it checkable.

Two things are verified:

  1. **Stability.** The same document is compiled several times under
     conditions that have historically broken reproducibility — a different
     hash seed, a different filesystem encoding — and every run must produce
     an identical tree.

  2. **The pinned hash.** Each tree is reduced to one SHA-256 over relative
     paths and file contents, and compared with `GOLDEN.sha256`. Because the
     hash is committed, a run on Linux and a run on Windows are compared with
     each other, not merely with themselves. It also means an unintended
     change to generated output fails loudly instead of passing quietly.

A failure here is not a style issue. Either the compiler acquired a source of
non-determinism, or its output changed and the pin was not updated on purpose.

Standard library only, Python 3.10+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
COMPILER = REPO / "compilers" / "acir_compiler_fastapi.py"
GOLDEN = REPO / "compilers" / "GOLDEN.sha256"

DOCUMENTS = ["examples/ecommerce-v0.3.acir.json"]

# Conditions that have actually broken byte-for-byte reproducibility before:
# randomized hashing changes set iteration order, and the filesystem encoding
# changes the bytes written for identical text.
CONDITIONS = [
    ("baseline", {}),
    ("hash-seed", {"PYTHONHASHSEED": "424242"}),
    ("utf8-mode", {"PYTHONUTF8": "1"}),
    ("legacy-encoding", {"PYTHONUTF8": "0", "PYTHONIOENCODING": "cp1252"}),
]


def compile_to(document: Path, out_dir: Path, env_overrides: dict) -> None:
    env = {**os.environ, **env_overrides}
    proc = subprocess.run(
        [sys.executable, str(COMPILER), str(document), str(out_dir)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    if proc.returncode != 0:
        tail = (proc.stderr.strip().splitlines() or ["no stderr"])[-1]
        raise SystemExit(f"compilation failed ({document.name}, {env_overrides}): {tail}")


def tree_hash(root: Path) -> str:
    """One hash over the whole tree.

    Paths are made relative and separators normalised, so the digest reflects
    the generated content rather than where it happened to be written or which
    OS wrote it.
    """
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda p: str(p.relative_to(root)).replace("\\", "/")):
        if path.is_file():
            digest.update(str(path.relative_to(root)).replace("\\", "/").encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--update", action="store_true",
                    help="Re-pin GOLDEN.sha256. Only after an intended change to the output.")
    args = ap.parse_args()

    pinned = json.loads(GOLDEN.read_text(encoding="utf-8")) if GOLDEN.exists() else {}
    fresh: dict[str, str] = {}
    failures: list[str] = []

    for rel in DOCUMENTS:
        document = REPO / rel
        print(f"\n{rel}")
        hashes: dict[str, str] = {}
        work = Path(tempfile.mkdtemp(prefix="acir-determinism-"))
        try:
            for label, env in CONDITIONS:
                out = work / label
                compile_to(document, out, env)
                hashes[label] = tree_hash(out)
                print(f"  {label:16} {hashes[label][:16]}")

            distinct = set(hashes.values())
            if len(distinct) != 1:
                failures.append(f"{rel}: output differs across conditions")
                print("  FAIL  the runs disagree with each other")
                for label, h in hashes.items():
                    print(f"          {label:16} {h}")
                continue

            digest = distinct.pop()
            fresh[rel] = digest

            if args.update:
                print(f"  pinned {digest[:16]}")
            elif rel not in pinned:
                failures.append(f"{rel}: no pinned hash")
                print(f"  FAIL  not in {GOLDEN.name} — run with --update if this document is new")
            elif pinned[rel] != digest:
                failures.append(f"{rel}: output changed")
                print("  FAIL  output no longer matches the pinned hash")
                print(f"          pinned {pinned[rel]}")
                print(f"          got    {digest}")
            else:
                print("  ok    matches the pinned hash")
        finally:
            shutil.rmtree(work, ignore_errors=True)

    if args.update:
        GOLDEN.write_text(json.dumps(fresh, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\n{GOLDEN.name} updated. Commit it with the change that caused it.")
        return 0

    if failures:
        print(f"\n{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        print("\nIf the change to the output was intended, re-pin with --update "
              "and say so in the commit message.")
        return 1

    print("\nDeterministic.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
