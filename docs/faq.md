# Frequently asked questions

Quick answers to questions that don't yet have their own doc. For anything deeper, follow the links — the full answer usually lives in a neighboring file.

## What's the difference between Hydra and the other siblings?

Hydra answers *"is it safe?"* — it scans configs at session start, gates dangerous actions before they run, detects secrets and vulnerabilities on every Write / Edit, and keeps an audit trail. Sibling plugins answer different questions: Wixie engineers prompts, Emu tracks token spend, Crow watches change trust, Sylph coordinates git workflow. All are independent installs. See [docs/ecosystem.md](ecosystem.md) for the full map.

## Do I need the other siblings to use Hydra?

No. Hydra is self-contained — install `full@hydra` and every command works standalone. It has zero runtime dependencies (bash + jq only).

## How do I report a bug vs. ask a question vs. disclose a security issue?

- **Security vulnerability** — private advisory, never a public issue. See [SECURITY.md](../SECURITY.md).
- **Reproducible bug** — a bug report issue with repro steps + exact versions.
- **Usage question or half-formed idea** — [Discussions](https://github.com/enchanter-ai/hydra/discussions).

The [SUPPORT.md](../SUPPORT.md) page has the exact links for each.

## Is Hydra an official Anthropic product?

No. Hydra is an independent open-source plugin for [Claude Code](https://github.com/anthropics/claude-code) (Anthropic's CLI). It's published by [enchanter-ai](https://github.com/enchanter-ai) under the MIT license and is not affiliated with, endorsed by, or supported by Anthropic.

## How do the 2,039 patterns relate to OWASP Top 10?

Each pattern belongs to exactly one rule class — Config / Action / Secret / Vuln / Phantom / Overflow — and the vuln-detector's patterns additionally cite OWASP LLM Top 10 categories (LLM01 Prompt injection, LLM02 Insecure output handling, LLM06 Sensitive information disclosure, etc.) and CWE IDs where they apply. The [glossary](glossary.md) has the full mapping table. Hydra does not claim to "replace" OWASP-trained scanners — it focuses on patterns specific to AI-assisted development contexts (poisoned hook configs, prompt-injection-to-RCE chains, LLM-specific exfiltration paths).

## Does Hydra block dangerous commands or just advise?

Advisory. Per the shared [hooks contract](../../vis/packages/core/conduct/hooks.md), Hydra's hooks inform — they don't decide. `action-guard` emits a severity-tagged warning on `PreToolUse(Bash)` matches; the user or orchestrator decides whether to proceed. The same is true of `config-shield`, `secret-scanner`, and `vuln-detector`. The audit trail records everything — finding, severity, verdict, user decision — for forensic review or compliance reporting.
