## What does this PR do?

<!-- One or two sentences. Link the related issue if any: Fixes #NNN -->

## Type of change

- [ ] Bug fix
- [ ] New feature / improvement (code, not spec)
- [ ] New compiler target (was discussed in a `new-target` issue: #NNN)
- [ ] Documentation / examples
- [ ] Spec change — ⚠️ stop: spec changes go through the [RFC process](../rfcs/README.md), not a direct PR

## Determinism checklist (required for validator/compiler changes)

- [ ] No timestamps, randomness, or environment-dependent values in generated output
- [ ] No network calls
- [ ] No new runtime dependencies (pure Python stdlib)
- [ ] Expected outputs updated if generated code changed
- [ ] Ran the compilation twice and diffed: outputs identical

## Tests

- [ ] New behavior is covered by tests
- [ ] Bug fixes include a test that fails without the fix

## DCO

- [ ] All commits are signed off (`git commit -s`)
