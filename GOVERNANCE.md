# Governance

This document describes how decisions are made in the ACIR project — and, just as importantly, how that is designed to change.

## The honest starting point

Today, ACIR has one maintainer: its original author. Pretending otherwise would be theater. What we can do instead is make single-maintainer governance as accountable as possible, and commit publicly to outgrowing it.

## How decisions are made today

**Code and documentation** (validator, compilers, CLI, docs): maintainer review and merge, standard open source flow. Disagreements are argued in the PR thread; the maintainer decides, with reasons.

**The specification** (anything that changes what the format *is*): public [RFC process](rfcs/README.md). Every substantial change is proposed, discussed, and decided in the open. The discussion thread is the permanent decision record. The maintainer makes the final call after the Final Comment Period, and a bare "no" is not a valid decision — every rejection must respond to the main arguments raised.

**The north star** used to arbitrate design conflicts, in strict priority order:

1. **Determinism** — same document + same compiler version = identical output, always.
2. **Auditability** — a document must be sufficient to prove what was generated.
3. **Target neutrality** — no primitive may exist to serve a single compilation target.
4. **LLM neutrality** — nothing in the format may depend on a specific model or vendor.
5. **Simplicity** — when everything above is satisfied, the smaller format wins.

A proposal that trades a higher value for a lower one carries the burden of proof.

## Committed evolution

Single-maintainer governance is a bootstrap arrangement, not a destination. The intended stages:

**Stage 1 — now.** Sole maintainer, public RFC process, reasoned decisions, response-time commitments (see CONTRIBUTING.md).

**Stage 2 — as contributors emerge.** Recurring contributors are invited as maintainers with merge rights on code. An RFC review group including non-founding contributors is formed; spec decisions move to rough consensus of that group.

**Stage 3 — at maturity.** Stewardship of the specification is transferred to an independent structure (foundation or equivalent), so that no single company — including the founder's — controls the standard.

Moving between stages is itself done through an RFC, so the community can hold the project to this document.

## Trademarks and commercial use

The names "ACIR" and related marks are held by Ld Labs. The specification and all code in this repository are Apache 2.0: use them, implement them, build commercial products on them — no permission needed. The marks exist to prevent confusing misrepresentation (e.g. calling a non-conformant format "ACIR"), not to restrict use.

## Changing this document

Through an RFC, like any other substantial change.
