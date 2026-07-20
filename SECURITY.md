# Security Policy

ACIR's core promise is that generated code is safe and auditable. Security reports are therefore treated as first-class contributions.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's **"Report a vulnerability"** button (Security tab → Private vulnerability reporting — enabled on this repository). If that channel is unavailable to you, open a plain issue saying only "security report — requesting a private channel", with **no technical details**, and a maintainer will arrange one.

Include if possible: the affected component (validator, a specific compiler, CLI), a minimal ACIR document reproducing the issue, and the generated output demonstrating the problem.

## What counts as a vulnerability here

- **Generated-code vulnerabilities**: any valid ACIR document that compiles into insecure code (injection, missing auth on mutations, missing rate limiting, unencrypted sensitive fields, etc.). These are the most important reports we can receive — they mean the validator's security rules have a gap.
- **Validator bypasses**: documents that should be rejected but pass validation.
- **Compiler issues**: path traversal via document contents, unsafe file writes, or any break of the "no network, no environment leakage" guarantees.
- **Determinism breaks with security impact**: outputs that differ between runs in ways affecting security posture.

## What to expect

- Acknowledgment within **72 hours**.
- An assessment and expected timeline within **7 days**.
- Coordinated disclosure: we ask that you give us up to **90 days** before public disclosure; we will credit you in the release notes unless you prefer otherwise.

No bug bounty exists yet — this is a young project — but reporters will be credited prominently, and the security rules added because of a report will reference it.

## Supported versions

Until v1.0 of the specification, only the latest released version of each component receives security fixes.
