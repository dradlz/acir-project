# ACIR Validator

Six-level validation pipeline for ACIR documents. This is the reference implementation of the specification's semantic rules — the second normative source after the [JSON Schema](../docs/schemas/acir-v0.3.2.json).

## Usage

```bash
# Optional but recommended: enables the JSON-Schema pass at level 1
pip install jsonschema

python validator/acir_validator.py examples/ecommerce-v0.3.acir.json
```

Output: human-readable summary plus structured, machine-readable issues (level, severity, JSON path, code, message, suggestion). Exit code 0 when valid. Without `jsonschema` installed, level 1 falls back to built-in structural checks (degraded but functional). Supports both `module` documents and `project` manifests, ACIR 0.2.0 (legacy) through 0.3.x.

## The six levels

| Level | Name | What it checks |
|---|---|---|
| **L1** | Structural | Document shape. v0.3: JSON Schema Draft 2020-12 (closed enums, `additionalProperties: false`); v0.2: built-in checks |
| **L2** | Semantic | `$ref` resolution, type compatibility, v0.3 extensions (transforms, validators, relations, `$loop`/`$auth` scoping) |
| **L3** | Contracts | Constraint satisfiability (compilable regexes, coherent bounds), `$calculate` DSL parsing |
| **L4** | Target compatibility | The document's intent is compilable to the requested target |
| **L5** | Security | OWASP-aligned analysis — see rules below. **Blocking**: an L5 error means no compilation |
| **L6** | Integration | Cross-module coherence (project manifests, component dependencies) |

## L5 security rules

These rules encode the project's core claim: a document that would compile into insecure code must not validate.

| Code | Rule |
|---|---|
| `MUTATION_NO_AUTH` | Any mutating endpoint (POST/PUT/PATCH/DELETE) must require authentication |
| `PUBLIC_NO_RATE_LIMIT` | Any public endpoint must declare a rate limit |
| `SENSITIVE_NO_ENCRYPT` | Sensitive fields must carry `C_ENCRYPT` |
| `SENSITIVE_DATA_NO_AUTH` | Endpoints returning sensitive data must require authentication |
| `SENSITIVE_IN_ERROR_MSG` | Error messages must not leak sensitive field values |
| `PASSWORD_NOT_SENSITIVE` | Password-like fields must be marked `sensitive` |
| `CRITICAL_MUTATION_NO_AUDIT` | Destructive mutations (DELETE/UPDATE) must carry `C_AUDIT` |
| `CRITICAL_POST_NO_IDEMPOTENT` | Critical POST operations must declare idempotency |
| `INPUT_STRING_NO_SANITIZE` | Public string inputs must carry `C_SANITIZE` |
| `EMAIL_NO_VALIDATION` | Email fields must carry a format validation |
| `STRING_NO_LENGTH` | String inputs must be length-bounded |
| `ENTITY_EXPOSED_DIRECTLY` | Persistence entities must not be exposed as API payloads directly |
| `INSECURE_HTTP_URL` | Outbound `IO_HTTP` calls must not use plain `http://` |
| `POSSIBLE_INLINE_SECRET` | Secret-looking literals must use `$secret`, never inline values |
| `ALL_ROLES_ALLOWED` | Role-based auth must not degenerate into allow-all |

Found a valid document that compiles into insecure code anyway? That's a gap in these rules — please report it privately first (see [SECURITY.md](../SECURITY.md)); it's the most valuable report this project can receive.

## Versioning

The validator carries its own version (`COMPILER_VERSION`) alongside the highest ACIR version it supports (`COMPILER_ACIR_VERSION`). Validation behavior changes follow the [RFC process](../rfcs/README.md) when they change what conformance means.
