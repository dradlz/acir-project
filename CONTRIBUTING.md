# Contributing to ACIR

Thanks for being here. ACIR only becomes a real standard if people other than its author shape it — so whether you're filing a typo fix or challenging a core primitive, you're doing the project a favor.

## Ways to contribute (all equally welcome)

**Critique the specification.** Read `spec/`, try to break it. A well-argued issue explaining why a primitive is wrong is one of the most valuable contributions possible at this stage.

**Bring a real-world case.** Try to express an actual service you've built in ACIR. If the format can't express it, open an issue with the label `expressiveness` describing what you needed. These issues drive the spec's evolution more than anything else.

**Fix bugs / improve code.** Validator, compilers, CLI, docs, examples — standard GitHub flow: fork, branch, PR.

**Build a compiler for a new target.** Open an issue first with the label `new-target` so we can help and avoid duplicate efforts. New targets do **not** require an RFC — the spec is the contract, the target is an implementation of it.

**Build an independent implementation.** Validators or compilers in other languages are explicitly encouraged. You don't need permission. Check yourself against [`conformance/`](conformance/README.md) — `python conformance/run.py --validator "your command"` — and if you want your implementation listed in the README, open a PR once it passes.

**Add a conformance case.** The corpus in `conformance/` pins down far less than the validator enforces, and every case added is one more thing an independent implementation can be held to. See [`conformance/README.md`](conformance/README.md) for how to write one; this is currently one of the most useful contributions available.

**Propose a change to the format itself.** That's an RFC — see [rfcs/README.md](rfcs/README.md). When in doubt whether your idea needs one, open an issue and ask; worst case we'll say "just send a PR."

## Ground rules for PRs

- One logical change per PR. Small PRs get reviewed fast; huge ones stall.
- Compilers must stay deterministic: no timestamps, no randomness, no environment-dependent output, no network calls. Any PR breaking this will be declined regardless of its other merits — determinism is the project's reason to exist.
- The validator keeps `jsonschema` as its only (optional) dependency; compilers, when published, are pure Python standard library. Adding any runtime dependency requires prior discussion in an issue.
- Generated-code changes must include the updated expected outputs so diffs stay reviewable.
- New behavior needs tests. Bug fixes need a test that fails without the fix.

## Running the checks

CI runs one script; run the same one locally before opening a PR:

```bash
python .github/scripts/ci_checks.py
```

It validates both examples, asserts on the machine-readable `--json` output
rather than on exit codes alone, checks that invalid documents are still
rejected, and exercises the reports under a legacy console encoding. Standard
library only, Python 3.10+.

Run it twice — with and without `jsonschema` installed. Both are supported
configurations, and only the second one exercises the degraded schema pass.

## Developer Certificate of Origin (DCO)

We use the [DCO](https://developercertificate.org/) instead of a CLA. It's a simple statement that you have the right to submit your contribution under Apache 2.0.

Sign every commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by:` line with your name and email. PRs with unsigned commits can't be merged (CI checks for it). No paperwork, no accounts, nothing to mail.

## Review expectations

- Every issue and PR gets a maintainer response within 72 hours. If we miss that window, ping the thread — the commitment is real.
- Reviews argue about the design, never the person.
- "No" always comes with "because". If you get a bare "no", you're entitled to ask why.

## Reporting security issues

Please don't open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).
