# ACIR — Agent Code Intermediate Representation

**A vendor-neutral, validated intermediate format between LLMs and production code.**

Any LLM writes it. A six-level validator checks it — structure, semantics, contracts, target compatibility, security, integration. Deterministic compilers turn it into production-grade code. Same document in, same code out — byte for byte, every time.

```
Natural language brief
        │
        ▼
   LLM (any model) ──────► ACIR document (structured JSON)
        ▲                        │
        │  invalid: sent back    ▼
        └────────────── 6-level validator
                        (structure, semantics, contracts,
                         target rules, security, integration)
                                 │ valid
                                 ▼
                    Deterministic compiler (per target)
                                 │
                                 ▼
              Production code + tests + Docker + README
```

## Why

AI code generation has a reproducibility problem: the same prompt produces different code on every run, which makes generated code hard to audit, certify, or trust in regulated environments.

Spec-driven development is a step in the right direction — make the LLM write a specification before writing code. But today every tool defines its own spec format, tied to its own agent, and in every one of them an LLM still writes the final code. The non-determinism has moved; it has not disappeared.

ACIR proposes to complete the chain, borrowing a pattern that industries like EDI settled decades ago:

1. **One standard format, LLM-agnostic and tool-agnostic.** Claude, GPT, Mistral, a local model — whoever writes, everyone writes to the same format. Change models, keep your specs.
2. **Validation before generation.** Every document is checked for structure *and* meaning — including 15 blocking security rules (mutations require auth, public endpoints require rate limits, sensitive fields require encryption, no inline secrets…). An invalid document goes back to the LLM, never to a compiler.
3. **Deterministic compilation.** A validated document becomes code through a mechanical, reproducible, auditable process. Creativity lives upstream, in interpreting intent. Downstream, no improvisation.

## What's in this repository today

| Component | Description | Status |
|---|---|---|
| **Specification** | [`spec/`](spec/README.md) — the format: 5 primitive families (Data, Flow, I/O, Contract, Composition), value expressions, module & project document kinds | **v0.3.x** |
| **JSON Schema** | [`docs/schemas/acir-v0.3.1.json`](docs/schemas/acir-v0.3.1.json) — normative shapes, Draft 2020-12, closed enums, `additionalProperties: false` | Normative |
| **Validator** | [`validator/`](validator/README.md) — the 6-level reference validator, including the 15 security rules. Single-file Python; optional `jsonschema` dependency for the schema pass | Working |
| **Generation tool** | [`tools/generate.py`](tools/README.md) — brief → LLM (Anthropic / OpenAI / Mistral, your key) → validated document, with automatic error-feedback retries; offline mock mode for CI | Working |
| **Examples** | [`examples/`](examples/README.md) — a stress-test e-commerce module, and a 3-microservice project manifest mixing Java/Quarkus, TypeScript/Fastify, and Python/FastAPI in one system | Validating 6/6 |

**Not published yet, coming next:** the deterministic compilers (Java/Quarkus, TypeScript/Fastify, Python/FastAPI, and the infrastructure compiler that derives Docker/compose from project manifests). They exist and are stable — they are being extracted from the platform codebase for standalone publication. Publishing the spec and validator first is deliberate: the format is the standard; compilers are implementations of it, and we want independent ones to be possible from day one.

## Try it now

```bash
git clone https://github.com/dradlz/acir-project.git && cd acir-project
pip install jsonschema   # optional, enables the JSON-Schema pass

python validator/acir_validator.py examples/ecommerce-v0.3.acir.json
# ✅ ACIR VALID — 6/6 levels passed
```

Generate your own document from a brief, with any LLM (your key, read from env):

```bash
export ANTHROPIC_API_KEY=...   # or OPENAI_API_KEY / MISTRAL_API_KEY
python tools/generate.py --provider anthropic \
  --brief "REST API for a product catalog with unique SKU, positive price, pagination, role-based auth"
```

The tool validates every response and feeds errors back to the model until the document passes — the generate→validate→correct loop this project is about, in one command. See [tools/README.md](tools/README.md).

Then open the example and break it on purpose: remove the `auth` block from a POST endpoint and re-validate — watch `MUTATION_NO_AUTH` block the document at level 5. That is the project's core claim in one command: **a document that would compile into insecure code does not validate.**

You can write ACIR by hand (start from the examples) or have any LLM produce it — the format is designed as an LLM target: strict canonical forms, closed enums, no synonyms, so the same brief converges to the same document.

## Status: early, open, looking for you

ACIR is at specification v0.3.x. The format works — but it is young, and it will only become genuinely useful if it is shaped by more perspectives than its author's.

This repository is published early, on purpose. What we are looking for right now:

- **Critique of the spec.** Read it, poke holes in it, tell us where the primitives are wrong, missing, or redundant. Open an issue — disagreement is a contribution.
- **Real-world briefs.** Try describing *your* actual back-end service in ACIR. Where the format can't express what you need, open an `expressiveness` issue — these drive the spec's evolution more than anything else.
- **Implementers.** Validators or compilers in other languages, compilers for other targets — independent implementations are explicitly welcome. The schema, the validator's rules, and the examples are the source of truth; conformant implementations will be listed here.
- **RFC participants.** Substantial evolution of the format happens through a public [RFC process](rfcs/README.md). No inner circle: the discussion thread is the decision record.

There is no fixed roadmap. The direction is set by the north star (determinism, auditability, target neutrality, LLM neutrality, simplicity — in that order) and by what the community actually needs. What gets built next is decided in the open.

## Determinism guarantee

The design constraint the compilers are built under, and that conformant implementations must uphold: given the same ACIR document and the same compiler version, output is **byte-for-byte identical** across runs and machines — no timestamps, no random identifiers, no environment leakage in generated code. This is what makes generated code auditable: archive the document, re-run the compilation years later, and prove what was generated.

## Licensing, patents, and what stays open

Everything in this repository — specification, schema, validator, examples, and the compilers when published — is licensed under **Apache 2.0**, permanently. Apache 2.0 includes an express patent grant: patents held on the ACIR format are licensed to you for use of this code. Adopting ACIR through this repository is safe by construction.

Full transparency: the maintainers also build a commercial hosted platform on top of ACIR (managed LLM orchestration, team workspaces, enterprise audit trail). The format and this repository do not depend on it and never will. Your documents and your generated code are yours. A standard that only works with one vendor's product is not a standard — that principle is the reason this repo exists.

## Contributing

- Start with [CONTRIBUTING.md](CONTRIBUTING.md). Short version: issues and PRs welcome, commits signed with `git commit -s` (DCO, no CLA).
- Substantial spec changes go through the [RFC process](rfcs/README.md); bug fixes don't.
- Governance is documented in [GOVERNANCE.md](GOVERNANCE.md) — including how it is designed to stop depending on its founder.
- Be excellent to each other: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security reports: [SECURITY.md](SECURITY.md) — a valid document that compiles into insecure code is our highest-priority bug class.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

ACIR format © Ld Labs. Patent pending (INPI). All patent rights necessary to use this software are granted under the Apache 2.0 patent clause.
