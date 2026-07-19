# ACIR Specification

## Normative sources

The ACIR specification is defined by two artifacts, in this order of authority:

1. **The JSON Schema** — [`../docs/schemas/acir-v0.3.1.json`](../docs/schemas/acir-v0.3.1.json) (Draft 2020-12). It defines the shapes: closed enums, required fields, `additionalProperties: false` everywhere. If the schema rejects a document, the document is not ACIR.
2. **The semantic rules of the validator** — [`../validator/acir_validator.py`](../validator/acir_validator.py), levels 2–6: `$ref` resolution, type compatibility, contract satisfiability, the `$calculate` DSL, target compatibility, security analysis, and cross-module integration. The schema says what a document *looks like*; the validator says what it *means* and whether it is safe.

A document is **conformant** when it passes both. Anything else in this repository (prose, examples, historical documents) is explanatory, not normative.

[`ACIR_SPEC-v0.2-historical.md`](ACIR_SPEC-v0.2-historical.md) is the original v0.2.0 prose specification. It is kept for the history of canonical-form decisions and their rationale, and is explicitly **non-normative**: v0.3 has since extended the format.

## The format in five minutes

An ACIR document is a JSON file describing a complete back-end application — data, logic, endpoints, and optionally its runtime — independently of any target language or framework.

Two document kinds exist:

- **Module** (`module` root): a single service — its types, business-logic units, exposed endpoints, and optional runtime block.
- **Project** (`acir_kind: "project"`): a manifest orchestrating several module documents into a system — per-component targets (one service in Java/Quarkus, another in TypeScript/Fastify, another in Python/FastAPI), dependencies between components, and shared infrastructure (databases, networking), from which Docker/compose files are derived.

### The five primitive families

| Prefix | Family | Role | Examples |
|---|---|---|---|
| `D_` | **Data** | Types: scalars, enums, records (entities & DTOs), collections, unions, aliases | `D_RECORD`, `D_ENUM`, `D_COLLECTION` |
| `F_` | **Flow** | Control flow: sequences (atomic or not), branches, guards, loops, error handling, retries | `F_SEQUENCE`, `F_GUARD`, `F_FOREACH`, `F_BRANCH` |
| `IO_` | **I/O** | Effects: queries, mutations, HTTP calls, messaging, cache, files, exposed endpoints | `IO_QUERY`, `IO_MUTATE`, `IO_EXPOSE`, `IO_HTTP` |
| `C_` | **Contract** | Declarative constraints compiled into validation, security and persistence code | `C_RANGE`, `C_UNIQUE`, `C_ENCRYPT`, `C_RATE_LIMIT`, `C_AUDIT` |
| `X_` | **Composition** | Business-logic units binding input, output and a flow body | `X_UNIT` |

Beyond the primitives, a module can declare **transforms** (pure data transformations), **validators** (named business rules referenced from guards), and **relations** (entity relationships with their FK semantics).

### Value expressions (`DataExpr`)

Wherever a value is needed, ACIR uses a closed expression language instead of free-form code: `{"$input": ...}` (unit argument), `{"$step": ...}` (previous step result), `{"$loop": ...}` (current iteration), `{"$auth": ...}` (authenticated principal), `{"$generate": "uuid" | "now" | {"kind": "template", ...}}`, `{"$calculate": {...}}` (arithmetic DSL, parsed and checked at validation time), `{"$validate": {...}}` (named business rule), `{"$secret": ...}` (environment secret), plus literals. The language is deliberately closed: everything a document can express, the validator can check and a compiler can translate deterministically.

### Canonical forms

ACIR admits **exactly one shape** for each pattern — synonym keys are rejected at validation, with an explicit error. One brief must always be expressible as one document; compilers must never have to support variants. The historical v0.2 document records these decisions and their rationale; the v0.3 schema enforces them mechanically (`additionalProperties: false`, closed enums).

## Versioning

Current specification line: **v0.3.x** (schema `acir-v0.3.1.json`; the validator tracks 0.3.2 and keeps back-compatibility with 0.2.0 documents). Semantic versioning applies — see the [RFC process](../rfcs/README.md) for how the specification evolves.

## Changing the specification

Any change to the shapes, the semantics, the guarantees, or the security rules goes through the public [RFC process](../rfcs/README.md). Gaps you hit in practice ("I couldn't express X") are `expressiveness` issues — they are the raw material of the spec's evolution, and very welcome.
