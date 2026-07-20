# Authoring ACIR documents

Three ways to produce an ACIR document, from most to least automated:

## 1. Generate with an LLM (recommended)

Use [`tools/generate.py`](../tools/README.md): your brief + your API key (Anthropic, OpenAI, or Mistral) → a document that has passed all 6 validation levels, or an explicit failure. The tool feeds validation errors back to the model, which is how ambiguity gets squeezed out: the LLM proposes, the validator disposes.

## 2. Prompt any LLM manually

Paste [`prompts/acir-system-prompt.md`](prompts/acir-system-prompt.md) as the system prompt in any chat interface, give your brief, and validate the output yourself:

```bash
python validator/acir_validator.py your-doc.acir.json
```

If it fails, paste the errors back to the model. This is exactly what `generate.py` automates.

## 3. Write it by hand

Start from [`../examples/`](../examples/) and the [spec](../spec/README.md). Hand-writing is the best way to *learn* the format — and the fastest way to find expressiveness gaps, which we want reported as `expressiveness` issues.

## Rules of thumb, whatever the method

- The validator is the contract. A document is done when it passes with 0 errors — not before, and there is no "close enough".
- Warnings are advice, not noise: they encode production practices (signup flows, sanitization, audit). Read them before ignoring them.
- One brief, one document: if you feel the urge to hand-tweak generated output, prefer refining the brief and regenerating — that keeps the brief the source of truth.
