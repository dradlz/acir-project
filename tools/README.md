# Tools

## `generate.py` — brief → LLM → validated ACIR

A miniature, open version of the generate→validate→correct pipeline. Your brief goes to the LLM of your choice; the response is validated by the 6-level validator; on errors, the structured issues are fed back and the LLM corrects — up to `--max-attempts` times.

```bash
export ANTHROPIC_API_KEY=...        # or OPENAI_API_KEY / MISTRAL_API_KEY

python tools/generate.py --provider anthropic \
  --brief "REST API for a product catalog with a unique SKU, positive 2-decimal price, pagination, role-based auth"

# → generated.acir.json, guaranteed 0 validation errors (or explicit failure)
```

Properties, by design:

- **Bring your own key.** Keys are read from environment variables only — never flags, never written anywhere.
- **LLM-agnostic.** `--provider anthropic | openai | mistral` (defaults: see `DEFAULT_MODELS`; model names age, override with `--model`). The same system prompt drives all three — that neutrality is the point of the format.
- **Errors only trigger retries.** Warnings and infos are advisory and reported, not looped on.
- **Offline mode for CI.** `--provider mock --mock-responses file1.json,file2.json` replays canned responses, one per attempt — no key, no network. The repo's own loop test:
  ```bash
  python tools/generate.py --provider mock \
    --mock-responses broken.acir.json,examples/ecommerce-v0.3.acir.json \
    --brief "test" --out /tmp/out.json
  ```
- Pure standard library; the only network calls are to the provider you explicitly chose.

The system prompt lives at [`../docs/prompts/acir-system-prompt.md`](../docs/prompts/acir-system-prompt.md) — it is a **reference** prompt, deliberately compact. Improving it (or specializing it per model) is a welcome contribution: the validator is the safety net that makes prompt iteration cheap.
