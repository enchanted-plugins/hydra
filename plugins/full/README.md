# full

**Meta-plugin. Installs every Hydra plugin at once.**

This plugin has no hooks, skills, or agents of its own. It exists so you can install the whole 15-plugin defense stack with one command:

```
/plugin marketplace add enchanter-ai/hydra
/plugin install full@hydra
```

Claude Code resolves the dependencies and installs the 15 functional plugins:

Scanner plugins (the original lineup, each with an agent):
- `hydra-action-guard` — pre-execution Bash command classifier (shadow-first 3-tier: deny/ask/warn)
- `hydra-audit-trail` — comprehensive security event logging
- `hydra-config-shield` — session-start repo-config poisoning scanner
- `hydra-secret-scanner` — real-time secret detection in writes
- `hydra-vuln-detector` — OWASP/CWE-mapped vulnerability detection

Advisory hook plugins:
- `hydra-package-gate` — pre-install supply-chain risk scoring
- `hydra-egress-monitor` — WebFetch/Bash-network destination logging
- `hydra-canary` — per-session injection canary tokens
- `hydra-capability-fence` — subagent-escape detection vs declared `allowed-tools`

Compliance plugins:
- `hydra-license-gate` — SPDX allow/deny over npm + pip dep trees
- `hydra-sbom-emitter` — CycloneDX SBOM generation

Opt-in / post-filter plugins:
- `hydra-capability-shield` — opt-in blocking sibling of capability-fence
- `hydra-egress-shield` — opt-in blocking sibling of egress-monitor
- `hydra-reach-filter` — call-graph reachability post-filter for vuln-detector
- `hydra-state-integrity` — HMAC-signed defense-state files; defense-of-defense layer

If you want to cherry-pick a single plugin (e.g. just `hydra-secret-scanner`), you can — but each plugin covers a different attack surface, so you'll typically want defense-in-depth.

## Behavioral modules

Inherits the [shared behavioral modules](../../shared/) via root [CLAUDE.md](../../CLAUDE.md) — discipline, context, verification, delegation, failure-modes, tool-use, skill-authoring, hooks, precedent.
