# action-guard

Pre-execution classification and blocking of dangerous Bash commands.

## Install

Part of the [Hydra](../..) bundle. The simplest install is the `full` meta-plugin, which pulls in all 15 Hydra plugins via dependency resolution:

```
/plugin marketplace add enchanter-ai/hydra
/plugin install full@hydra
```

To install this plugin on its own: `/plugin install hydra-action-guard@hydra`. `action-guard` classifies every Bash command into one of three enforcement tiers — **deny** (catastrophic/irreversible: filesystem/system destruction, backdoors, remote-exec pipes, whole-table/database wipes), **ask** (costly-but-legitimate infra ops), and **warn** (everything else worth flagging) — per VF-05. Rollout is **shadow-first**: the default `enforce_mode` is `shadow`, which classifies and logs `would_deny`/`would_ask`/`would_warn` to `state/audit.jsonl` and blocks nothing. Flipping to `enforce` makes the tiers real: deny -> `permissionDecision: "deny"`, ask -> `permissionDecision: "ask"`, warn -> stderr advisory, and exits 0 in every case. The deny tier is pinned by the git-tracked, read-only `policy.json` — the agent-writable `state/config.json` may only raise strictness, never lower the deny floor. Defense-in-depth still applies: `secret-scanner` catches the exfil payload on disk, `config-shield` catches the poisoned config that would mute the hook, `vuln-detector` catches the RCE bug upstream, and `audit-trail` records every event for incident review.

## Algorithms
- **R4: Markov Action Classification** — classify commands as SAFE/WARN/ASK/DENY
- **R7: Subcommand Overflow Detection** — deny 50+ subcommand deny-rule bypass

## Hook
- **PreToolUse** on Bash — classifies command BEFORE execution
- **Shadow-first, 3-tier enforcement** — `enforce_mode` defaults to `shadow` (classify + log only, blocks nothing). In `enforce` mode: deny -> `permissionDecision: "deny"`, ask -> `permissionDecision: "ask"`, warn -> stderr advisory (`=== action-guard (advisory) ===` / `Would have blocked: …` / `Hint: …`). Always exits 0 — Claude Code's `permissionDecision` output carries the verdict. See [`../vis/packages/core/conduct/hooks.md`](../../../vis/packages/core/conduct/hooks.md).

## Strictness Modes
| Mode | Block patterns | Warn patterns |
|------|---------------|---------------|
| strict | BLOCK | BLOCK |
| balanced (default) | BLOCK | WARN |
| permissive | WARN | WARN |

## What Triggers Each Tier
- **deny**: `rm -rf /`, filesystem/system destruction, `DROP TABLE`/`TRUNCATE`/database drops, `curl \| bash`/`wget \| bash`, reverse shells, `shutdown`/`reboot`, `kill -9 -1`, overwriting `/etc/{passwd,shadow,sudoers}`, 50+ subcommand overflow
- **ask**: costly-but-legitimate infra ops (e.g. force push to main/master)
- **warn**: lower-severity dangerous-ops matches not promoted to ask/deny

In `shadow` mode every match is recorded to `state/audit.jsonl` as a `would_*` event and execution proceeds. In `enforce` mode, deny and ask actually gate the tool call; only warn is advisory.

## Command
`/hydra:safety` — show mode, recent blocks, classify commands

## Agent
`guardian` (Sonnet) — evaluate ambiguous commands with full context

## Behavioral modules

Inherits the [shared behavioral modules](../../shared/) via root [CLAUDE.md](../../CLAUDE.md) — discipline, context, verification, delegation, failure-modes, tool-use, skill-authoring, hooks, precedent.
