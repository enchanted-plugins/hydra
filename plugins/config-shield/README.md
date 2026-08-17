# config-shield

Session-start scanning for malicious repository configuration files.

## Install

Part of the [Hydra](../..) bundle. The simplest install is the `full` meta-plugin, which pulls in all 5 Hydra plugins via dependency resolution:

```
/plugin marketplace add enchanter-ai/hydra
/plugin install full@hydra
```

To install this plugin on its own: `/plugin install hydra-config-shield@hydra`. `config-shield` fires once at session start — it catches the poisoned `.claude/settings.json` that would silence `action-guard`, the hook that would exfil secrets past `secret-scanner`, the VS Code settings that would load backdoored code past `vuln-detector`, and it writes every finding to `audit-trail`. It's the first line; without the other four, there's no second line.

## Algorithm
- **R5: Config Poisoning Detection** — known-attack signature matching (14 of the 122 signatures carry a specific CVE, mapping to 7 distinct CVE IDs; see table below)
- **R-019: Signed Config Integrity** — HMAC-SHA-256 sidecar signatures on `.claude/settings*.json` and `hooks/hooks.json`. SessionStart verifies; PreToolUse warns on writes to signed configs.

## Hooks
- **SessionStart** — scans repo for poisoned configs (`scan-config.sh`) and verifies signature sidecars (`verify-signatures.sh`)
- **PreToolUse** (`Edit`/`Write`/`MultiEdit`) — emits advisory when a write targets a signed-config path (`pretooluse-config-write.sh`)

## Signed Config Workflow (R-019)

A single Write to `.claude/settings.json` could otherwise disable every Hydra defense and leave no chain anomaly. The signing layer closes that gap.

1. **Install / after every config change:** operator runs `bash plugins/config-shield/scripts/sign-all.sh` from the repo root. Each `.claude/settings*.json` and `hooks/hooks.json` gets a sidecar `<file>.sig` (HMAC-SHA-256 of canonicalised content).
2. **SessionStart:** `verify-signatures.sh` walks every config in the cwd ancestor chain + any plugin `hooks/hooks.json`. Mismatch → stderr advisory. Missing sidecar → info-level advisory. Always exits 0 (advisory contract) unless policy says otherwise.
3. **Write detection:** PreToolUse hook emits a reminder to re-sign when the agent edits a signed-config path. Advisory only — never blocks.
4. **Opt-in blocking:** copy `state/config-shield-policy.example.json` → `state/config-shield-policy.json` and set `fail_on_signature_mismatch: true` to make SessionStart exit non-zero on mismatch.

### Scripts
- `scripts/sign-config.sh <file>` — sign one file (writes `<file>.sig`)
- `scripts/verify-config.sh <file>` — exit `0` match / `1` mismatch / `2` no sig
- `scripts/sign-all.sh [root]` — recursive sign sweep over cwd or `<root>`

### Key sourcing
Identical priority to `audit-trail/scripts/chain-helpers.sh`:
1. `$HYDRA_AUDIT_HMAC_KEY` env var (operator-rotated)
2. `state/hmac-key.bin` (auto-generated 256-bit, mode 0600)
3. Plain SHA-256 with a loud warning — never silent.

## Attack Vectors Detected
| CVE | File | Attack |
|-----|------|--------|
| CVE-2025-59536 | .claude/settings.json | Hooks execute shell commands on clone |
| CVE-2026-21852 | .claudecode/settings.json | API key theft via base URL override |
| CVE-2025-54135 | .cursor/mcp.json | Persistent RCE via MCP server |
| — | .vscode/tasks.json | Auto-run on folder open |
| — | package.json | Malicious lifecycle scripts |
| — | .cursorrules | Hidden Unicode prompt injection |
| — | .mcp.json | MCP consent bypass |

## Command
`/hydra:config-check` — scan all config files with CVE references

## Agent
`inspector` (Sonnet) — deep analysis with base64 decode and Unicode detection

## Behavioral modules

Inherits the [shared behavioral modules](../../shared/) via root [CLAUDE.md](../../CLAUDE.md) — discipline, context, verification, delegation, failure-modes, tool-use, skill-authoring, hooks, precedent.
