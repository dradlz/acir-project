# RFC 0008 — Settle the severity of a non-`snake_case` field name

- **Status:** Draft
- **Author(s):** @dradlz
- **Discussion PR:** https://github.com/dradlz/acir-project/pull/8
- **Spec version target:** 0.3.2

## Summary

A field name that is not `snake_case` is rejected as an **error** by the
normative JSON-Schema and reported as a **warning** by the validator's
hand-written pass. The same document is therefore accepted or refused
depending on which code path ran. This RFC asks the project to pick one, and
argues for *warning*.

## Motivation

This is not a hypothetical. It was found while building the conformance
corpus, by running every candidate case with and without the optional
`jsonschema` dependency and comparing verdicts:

```
$ python validator/acir_validator.py bad-field-name.acir.json   # with jsonschema
❌ ACIR INVALID — stopped at level 1

$ python validator/acir_validator.py bad-field-name.acir.json   # without
✅ ACIR VALID — 6/6 levels passed (level 1 degraded: normative JSON-Schema NOT applied)
```

The document is `valid/read-endpoint.acir.json` with `id` renamed to
`ThingId`, and nothing else.

Two things make this worth an RFC rather than a bug fix.

**It is a spec question, not an implementation slip.** Both behaviours are
deliberate. The schema declares `"pattern": "^[a-z][a-z0-9_]*$"` on field
names; the hand-written pass emits `FIELD_NAME_FORMAT` at `WARNING`. Someone
decided each of those. Nothing in the spec says which one is normative, so
neither can be called the bug.

**It makes the case unrepresentable in the conformance suite.** The corpus
requires every case to produce the same verdict regardless of optional
dependencies — otherwise two honest implementations disagree and the format
has no answer to give them. This case is therefore excluded today, which
means a naming rule the format clearly cares about is one that independent
implementations cannot be held to at all.

## Detailed design

Adopt **warning** as the normative severity. Concretely:

- **Format change.** Remove the `pattern` constraint from field names in
  `docs/schemas/acir-v0.3.1.json`. Naming stops being a structural
  constraint.
- **Validation rules.** Level 1 keeps `FIELD_NAME_FORMAT` at `WARNING`,
  unchanged. No level gains or loses a rule.
- **Spec text.** State explicitly that field naming is a *convention the
  format reports on*, not a structural requirement — and that the same
  applies to any future naming rule unless it says otherwise.
- **Conformance.** Add the case to the corpus as `warning/field-name-format`,
  in the same shape as `warning/mutation-without-auth`: a valid document that
  must still be reported on.
- **Compiler targets.** No impact on what compilers accept. Some already
  normalise identifiers to their language's convention (`created_at` becomes
  `createdAt` in the TypeScript target), which is an argument that ACIR-side
  naming was never load-bearing for code generation.
- **Determinism.** Unaffected. Naming does not enter the compilation
  contract.

## Drawbacks

**It weakens a canonical form.** "One form per pattern, synonyms rejected" is
a core principle, and `userId` versus `user_id` is a synonym pair by any
reasonable reading. Demoting it to a warning is a real, if narrow, retreat
from that principle.

**Warnings get ignored.** A rule that never blocks anything is a rule that
drifts. If the answer is warning, the corpus case matters more than usual: it
is what stops implementations from quietly dropping the check entirely.

**It is the less strict of the two options,** and this project's instinct has
generally been to prefer the stricter one. That instinct deserves to be
argued with rather than assumed here.

## Alternatives considered

**Promote to error (make the hand-written pass reject it).** Coherent, and
arguably more in keeping with the canonical-forms principle. Rejected as the
recommendation for two reasons. It breaks every existing document that
happens to use a camelCase field name, with no migration beyond "rename your
fields" — a real cost for a rule that changes nothing about the generated
code. And it makes the strictness of the format depend on an optional
dependency being installed, which is the deeper problem: an implementation
without a JSON-Schema library would have to hand-write the pattern check to
stay conforming, for a rule that buys it nothing.

**Do nothing.** The status quo is not stable. It is not that the ambiguity is
tolerable — it is that it is currently *invisible*, and it stops being
invisible the moment someone writes a second implementation. Better to answer
it now, cheaply, than after someone has shipped a validator that disagrees
with ours.

**Make it configurable (strict mode).** Two conformance profiles, two sets of
verdicts, twice the surface for implementations to diverge across. A format
this young cannot afford dialects.

## Backward compatibility

Under the recommendation, every currently valid document stays valid, and
some currently invalid ones become valid-with-a-warning. Nothing to migrate.

Under the rejected alternative (promote to error), documents using camelCase
field names would break, and that path would need a deprecation window.

## Open questions

- Does this generalise? `MODULE_NAME_FORMAT` (PascalCase modules) is a
  warning in the same pass — is *its* schema constraint consistent, and are
  there other naming rules with the same split? A sweep of all pattern
  constraints in the schema should happen before this is decided, and might
  turn this RFC into a broader one about where naming rules live.
- Should a warning that is part of the conformance contract be marked as such
  in the report, so implementations can tell "you must emit this" apart from
  "we happen to emit this"? That is arguably a separate RFC, but it is what
  gives the recommendation its teeth.
