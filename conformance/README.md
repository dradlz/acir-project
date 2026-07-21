# ACIR conformance suite

A corpus of small ACIR documents with the verdict each one must receive. It
exists so that an implementation written by someone else can prove it agrees
with this one — without reading a line of the reference validator.

If you are writing a validator, a compiler front-end, or anything else that
consumes ACIR, this is the contract.

## Running it

Against the reference validator:

```bash
python conformance/run.py -v
```

Against your own:

```bash
python conformance/run.py --validator "node my-validator.js"
```

Run it **twice — with and without `jsonschema` installed**. Every case in the
corpus is required to produce the same verdict either way (see *Optional
dependencies* below).

## The corpus is data, not code

`manifest.json` and `cases/` are plain JSON and contain nothing
Python-specific. `run.py` is one harness over that data; porting it means
reimplementing a single function, `report_for()`. If your implementation is
not a CLI, or does not speak our report format, write your own harness — the
corpus is the contract, the harness is not.

Each manifest entry looks like this:

```json
{
  "id": "invalid/delete-without-auth",
  "document": "cases/invalid/delete-without-auth.acir.json",
  "expect": {
    "valid": false,
    "issues": [{ "code": "MUTATION_NO_AUTH", "level": 5, "severity": "error" }]
  }
}
```

## What conformance means

An implementation conforms when, for every case:

1. **The verdict matches.** `valid` is exactly what the manifest says.
2. **Every listed issue is reported**, with the same `code`, `level` and
   `severity`.

Three consequences worth stating outright, because each one has already
caught a real mistake:

**Codes are the contract; messages are not.** Wording changes between
releases and is expected to differ between implementations. Never match on
message text — `code` is the stable identifier.

**Severity is part of the contract, not decoration.** Compare
`invalid/delete-without-auth` with `warning/mutation-without-auth`: same rule,
same code, but an unauthenticated `DELETE` is blocking where an
unauthenticated `POST` only warns. An implementation that promotes the warning
to an error is as non-conforming as one that demotes the error.

**Reporting less is failing, even when the verdict is right.**
`warning/mutation-without-auth` is a *valid* document that must still be
reported on. An implementation that silently accepts it agrees on the verdict
and is still wrong — a warning nobody emits is a rule nobody enforces.

**Reporting more is allowed.** Matching is subset-based: extra advisories,
finer-grained findings, or additional levels are all fine. You may report more
than the corpus requires; you may never report less, and you may never
disagree on the verdict.

## Optional dependencies must not change a verdict

The reference validator treats `jsonschema` as an optional dependency: without
it, the normative JSON-Schema pass is skipped and only the hand-written checks
run. Every case in this corpus is chosen so the verdict is identical either
way, and CI runs the suite in both configurations.

This is not a detail of our packaging. A document whose acceptance depends on
which optional pieces an implementation happens to have installed cannot be a
conformance case at all — two honest implementations would disagree about it,
and the format would have no answer. Such documents are excluded here, and
finding one is a bug report against the spec, not against your validator.

> One is known: a field name that is not `snake_case` is an **error** under
> the JSON-Schema and a **warning** in the hand-written pass, so the verdict
> flips with the dependency. It is deliberately absent from the corpus until
> the spec settles which one is right.

## Adding a case

1. Write the smallest document that triggers exactly one rule. Start from
   `cases/valid/read-endpoint.acir.json` and break one thing.
2. Add an entry to `manifest.json` with the verdict and required issues.
3. Run `python conformance/run.py -v` with **and** without `jsonschema`. If
   the two runs disagree, the case does not belong here — see above.
4. Write the `note` for someone who has never read the validator. Say what
   the rule protects against, not what the code is called.

Cases are grouped by what they assert, not by which level fires:
`valid/` must be accepted, `invalid/` must be rejected, `warning/` must be
accepted *and* reported on.

## Current coverage

Eleven cases: the document shapes that must be accepted, the canonical-form
rules (synonyms are rejected, never tolerated), reference resolution, and the
security rules around authentication.

This is a floor, not a ceiling — the validator implements far more rules than
the corpus pins down. Contributions that add cases are among the most useful
ones possible right now: every case added is one more thing an independent
implementation can be held to.
