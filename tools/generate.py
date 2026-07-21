#!/usr/bin/env python3
"""acir-gen — generate an ACIR document from a natural-language brief, with any LLM,
and validate it in a retry loop.

This is a miniature, open version of the generate→validate→correct pipeline:
  E1  the LLM turns your brief into an ACIR document
  E2  the 6-level validator checks it (structure, semantics, contracts, security…)
  E3  on errors, the structured issues are fed back to the LLM, which corrects

Bring your own key (environment variables, never flags):
  ANTHROPIC_API_KEY | OPENAI_API_KEY | MISTRAL_API_KEY

Examples:
  python tools/generate.py --provider anthropic \
      --brief "REST API for a product catalog with unique SKU, positive price, pagination"
  python tools/generate.py --provider mistral --brief-file brief.txt --out my-service.acir.json
  python tools/generate.py --provider mock --mock-responses examples/ecommerce-v0.3.acir.json \
      --brief "anything"   # offline test / CI

Pure standard library. No telemetry, no network beyond the provider you choose.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "validator"))
from acir_validator import ACIRValidator, Severity, force_utf8_output  # noqa: E402

SYSTEM_PROMPT_PATH = REPO_ROOT / "docs" / "prompts" / "acir-system-prompt.md"

DEFAULT_MODELS = {
    # Model names age quickly — override with --model if these are outdated.
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "mistral": "mistral-large-latest",
}


# ─── Providers ────────────────────────────────────────────────────────────────

def _post_json(url: str, headers: dict, payload: dict, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:2000]
        raise SystemExit(f"Provider HTTP {e.code}: {body}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Network error reaching provider: {e.reason}")


def call_anthropic(model: str, system: str, messages: list[dict]) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY") or _missing("ANTHROPIC_API_KEY")
    data = _post_json(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": key, "anthropic-version": "2023-06-01"},
        {"model": model, "max_tokens": 8192, "system": system, "messages": messages},
    )
    return "".join(b.get("text", "") for b in data.get("content", []))


def _call_openai_style(url: str, key: str, model: str, system: str, messages: list[dict]) -> str:
    msgs = [{"role": "system", "content": system}] + messages
    data = _post_json(url, {"Authorization": f"Bearer {key}"},
                      {"model": model, "messages": msgs})
    return data["choices"][0]["message"]["content"]


def call_openai(model: str, system: str, messages: list[dict]) -> str:
    key = os.environ.get("OPENAI_API_KEY") or _missing("OPENAI_API_KEY")
    return _call_openai_style("https://api.openai.com/v1/chat/completions", key, model, system, messages)


def call_mistral(model: str, system: str, messages: list[dict]) -> str:
    key = os.environ.get("MISTRAL_API_KEY") or _missing("MISTRAL_API_KEY")
    return _call_openai_style("https://api.mistral.ai/v1/chat/completions", key, model, system, messages)


def _missing(var: str):
    raise SystemExit(f"Missing environment variable {var}. Export it and retry "
                     f"(your key is never passed as a flag or written to disk).")


class MockProvider:
    """Replays canned responses from files — one per attempt. For offline tests and CI."""

    def __init__(self, paths: list[str]):
        self.responses = [Path(p).read_text(encoding="utf-8") for p in paths]
        self.i = 0

    def __call__(self, model: str, system: str, messages: list[dict]) -> str:
        if self.i >= len(self.responses):
            raise SystemExit("Mock provider exhausted: more attempts than --mock-responses files.")
        out = self.responses[self.i]
        self.i += 1
        return out


# ─── Pipeline ─────────────────────────────────────────────────────────────────

FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.MULTILINE)


def extract_json(text: str) -> dict:
    """Tolerant extraction: strip Markdown fences, then take the outermost {...}."""
    cleaned = FENCE_RE.sub("", text).strip()
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in the model response.")
    return json.loads(cleaned[start:end + 1])


def issues_for_feedback(result) -> list[dict]:
    """Errors only — warnings/info are advisory and must not trigger retries."""
    return [i.to_dict() for i in result.issues if i.severity == Severity.ERROR]


def run(provider_fn, model: str, brief: str, max_attempts: int, out_path: Path) -> int:
    system = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")
    validator = ACIRValidator()
    messages = [{"role": "user", "content": f"Brief:\n{brief}"}]

    for attempt in range(1, max_attempts + 1):
        print(f"── Attempt {attempt}/{max_attempts}: generating…")
        raw = provider_fn(model, system, messages)

        try:
            doc = extract_json(raw)
        except (ValueError, json.JSONDecodeError) as e:
            print(f"   ✗ Unparseable response ({e}); asking for JSON only.")
            messages += [{"role": "assistant", "content": raw},
                         {"role": "user", "content":
                          "Your response was not a parseable JSON document. "
                          "Return ONLY the complete ACIR JSON object — no prose, no fences."}]
            continue

        result = validator.validate(doc)
        errors = issues_for_feedback(result)
        n_warn = sum(1 for i in result.issues if i.severity == Severity.WARNING)

        if result.valid and not errors:
            out_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            print(f"   ✓ Valid on attempt {attempt} ({n_warn} warning(s)).")
            print(f"── Written to {out_path}")
            return 0

        print(f"   ✗ {len(errors)} validation error(s); feeding them back.")
        for e in errors[:5]:
            print(f"     [{e['code']}] {e['path']}: {e['message']}")
        if len(errors) > 5:
            print(f"     … and {len(errors) - 5} more")

        messages += [
            {"role": "assistant", "content": json.dumps(doc, ensure_ascii=False)},
            {"role": "user", "content":
             "The document failed validation. Fix EVERY issue below and return the "
             "complete corrected ACIR JSON document (JSON only):\n"
             + json.dumps(errors, indent=2, ensure_ascii=False)},
        ]

    print(f"── Gave up after {max_attempts} attempts. Last errors above.")
    return 1


def main() -> int:
    force_utf8_output()

    ap = argparse.ArgumentParser(description="Generate an ACIR document with an LLM and validate it.")
    ap.add_argument("--provider", required=True, choices=["anthropic", "openai", "mistral", "mock"])
    ap.add_argument("--model", help="Model name (defaults per provider; names age — override freely).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--brief", help="The natural-language brief, inline.")
    g.add_argument("--brief-file", help="Path to a text file containing the brief.")
    ap.add_argument("--out", default="generated.acir.json", help="Output path (default: generated.acir.json)")
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--mock-responses", help="Comma-separated response files (provider=mock only).")
    args = ap.parse_args()

    brief = args.brief or Path(args.brief_file).read_text(encoding="utf-8")

    if args.provider == "mock":
        if not args.mock_responses:
            ap.error("--mock-responses is required with --provider mock")
        provider_fn = MockProvider(args.mock_responses.split(","))
        model = "mock"
    else:
        provider_fn = {"anthropic": call_anthropic, "openai": call_openai, "mistral": call_mistral}[args.provider]
        model = args.model or DEFAULT_MODELS[args.provider]

    return run(provider_fn, model, brief, args.max_attempts, Path(args.out))


if __name__ == "__main__":
    sys.exit(main())
