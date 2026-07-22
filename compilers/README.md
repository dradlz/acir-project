# Compilers

A compiler turns a validated ACIR document into a runnable project. This is
the second half of the claim the whole format rests on: creativity upstream,
mechanical translation downstream.

| Target | File | Status |
|---|---|---|
| Python / FastAPI | `acir_compiler_fastapi.py` | Published |
| Java / Quarkus | — | Being extracted |
| TypeScript / Fastify | — | Being extracted |
| Infrastructure (Docker/compose) | — | Being extracted |

## Running it

```bash
python compilers/acir_compiler_fastapi.py examples/ecommerce-v0.3.acir.json ./out
```

Validate first — the compiler assumes a valid document and does not re-check
the semantic rules:

```bash
python validator/acir_validator.py examples/ecommerce-v0.3.acir.json
```

Standard library only, Python 3.10+. The generated project has its own
dependencies (FastAPI, SQLAlchemy, Pydantic); the compiler itself has none.

## Determinism

The same document must compile to the same bytes, every run, on every
machine. Not "the same behaviour" — the same bytes. A generated project that
differs between runs cannot be reviewed, diffed, or certified, and the
argument for compiling from a specification instead of prompting for code
falls apart.

That claim is checkable:

```bash
python compilers/determinism_check.py
```

It compiles each reference document several times — different hash seed,
different filesystem encoding — and requires every run to produce an identical
tree. The tree is then reduced to a single SHA-256, compared against
`GOLDEN.sha256`. Because that hash is committed, a Linux run and a Windows run
are compared with each other, not merely with themselves. CI runs it on both.

**If you change the compiler's output on purpose**, re-pin and say so:

```bash
python compilers/determinism_check.py --update   # then commit GOLDEN.sha256
```

A pin that changes without an explanation in the commit message is the thing
this file exists to catch.

## Writing a compiler

Nothing about the format privileges these implementations. If you are
building one:

- Start from `conformance/` — it is the shortest statement of what a
  conforming implementation must agree with, and `conformance/run.py` will
  tell you where you stand.
- Determinism is not negotiable and is the one thing a PR will be declined
  over regardless of its other merits. The usual sources are timestamps,
  unsorted iteration over sets and dicts, absolute paths, locale-dependent
  encoding, and the platform's line ending. Pin encoding and newline
  explicitly on every write; sort before you emit.
- A new target does not need an RFC. Open a `new-target` issue and we will
  help.

Two rules worth stating because they were learned the hard way here: never
write files with a bare `open(path, "w")`, and never let anything that is not
in the input document reach the output.
