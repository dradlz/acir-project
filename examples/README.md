# Examples

Real ACIR documents, validating cleanly against the current validator — the module
against all six levels, the project manifest against the two that apply to it. They double as the de facto conformance material for independent implementations.

| File | Kind | What it demonstrates |
|---|---|---|
| `ecommerce-v0.3.acir.json` | Module | A single service under stress: enums, entities with contracts (`C_RANGE`, `C_PRECISION`), relations, a pure transform, a named business validator, atomic sequences, `F_FOREACH`, `F_GUARD` with typed failure, `$auth`/`$generate`/`$calculate` expressions, authenticated endpoints |
| `booking-platform-project-v0.3.acir.json` | Project | A 3-microservice system (auth / catalog / booking) with **one target per component** — Python/FastAPI, TypeScript/Fastify, Java/Quarkus — dependencies between components, and shared infrastructure (PostgreSQL, per-component DB isolation) |

Validate any of them:

```bash
python validator/acir_validator.py examples/ecommerce-v0.3.acir.json
```

Note: the project manifest references component documents (`auth.acir.json`, …) not included here yet; it demonstrates the manifest layer itself. Secrets in examples are obvious placeholder values — never ship real ones in a document; use `{"$secret": "NAME"}`.

Have a real-world service ACIR can't express? Open an `expressiveness` issue — that's exactly what we're looking for.
