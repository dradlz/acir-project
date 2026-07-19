# ACIR RFC Process

RFC ("Request for Comments") is how substantial changes to the ACIR specification are proposed, discussed, and decided — in public. If you want to change what the format *is*, this is the path. It exists so the evolution of ACIR is driven by arguments anyone can read, not by decisions made in private. There is no roadmap handed down from above: this process **is** the roadmap.

## When an RFC is required

You **need** an RFC for anything that changes the specification or its guarantees:

- Adding, removing, or changing a primitive (any of the 5 families: Data, Flow, I/O, Contract, Composition)
- Changing the semantics of an existing primitive
- Adding or modifying validation levels or validation rules (including OWASP rules)
- Changing the determinism guarantees or the conformance requirements for compilers
- Breaking changes of any kind to the document format
- Changes to governance or to this process itself

You do **not** need an RFC for:

- Bug fixes in the validator or compilers
- A new compiler target that implements the existing spec (open a `new-target` issue instead — we'll help)
- Documentation, examples, tooling, CI
- Performance improvements with no observable behavior change

Not sure? Open an issue and ask. Worst case, we'll say "just send a PR."

## Lifecycle

```
Idea ──► Pre-discussion (issue) ──► Draft PR ──► Discussion ──► FCP ──► Accepted / Rejected ──► Implemented
```

**1. Pre-discussion (recommended, not mandatory).**
Open a GitHub issue with the `rfc-idea` label describing the problem and a sketch of the solution. This avoids writing a full RFC for something that has an existing answer or a known blocker.

**2. Draft.**
Copy `rfcs/0000-template.md` to `rfcs/0000-my-feature.md` and fill it in. Open a pull request. The PR number becomes the RFC number (rename the file accordingly). The RFC is now in **Draft**.

**3. Discussion.**
The PR is the discussion thread. Anyone may comment. The author is expected to revise the text as arguments land — the final text should reflect the discussion, including the objections. Minimum discussion period: **14 days**. Complex RFCs commonly take longer; there is no maximum.

**4. Final Comment Period (FCP).**
When discussion converges (arguments are repeating, open questions are resolved or explicitly deferred), a maintainer proposes FCP with a disposition: *accept* or *reject*. FCP lasts **7 days** and is announced on the PR. This is the "speak now" window: new substantive arguments during FCP cancel it and return the RFC to Discussion.

**5. Decision.**
After FCP, the maintainers decide (see [GOVERNANCE.md](../GOVERNANCE.md) for who that is and how it evolves). Accepted RFCs are merged with status **Accepted**; the PR discussion is preserved as the permanent record of *why*. Rejected RFCs are closed with a written rationale — rejection with reasons is a contribution too — and listed in `rfcs/REJECTED.md` so ideas aren't re-litigated from scratch.

**6. Implementation.**
Acceptance means "this belongs in the spec," not "someone will build it tomorrow." An accepted RFC gets a tracking issue. When implemented and released, its status becomes **Implemented**, tagged with the spec version that shipped it.

## Statuses

| Status | Meaning |
|---|---|
| `Draft` | Open PR, under discussion |
| `FCP` | Final comment period, disposition announced |
| `Accepted` | Merged, awaiting implementation |
| `Implemented` | Shipped in a spec release |
| `Rejected` | Closed with rationale |
| `Withdrawn` | Author withdrew it |
| `Superseded` | Replaced by a later RFC (linked) |

## Decision rules

- Decisions are made in public, on the RFC thread, after FCP.
- Every decision must respond to the main arguments raised. "No, because" is required; "no" alone is not acceptable.
- The spec's north star, in strict priority order: **determinism, auditability, target neutrality, LLM neutrality, simplicity**. An RFC that trades a higher value for a lower one carries the burden of proof.
- Silence is not consensus; FCP exists so that consensus is tested, not assumed.

## Spec versioning

The ACIR specification follows semantic versioning:

- **Patch** (0.2.x): clarifications, no behavior change.
- **Minor** (0.x.0): additive, backward-compatible (new primitives, new optional fields). Documents valid under 0.2 remain valid under 0.3.
- **Major** (x.0.0): breaking changes. Requires an RFC, a migration guide, and a deprecation period of at least one minor release with warnings in the validator.

Compilers declare the spec version range they support.
