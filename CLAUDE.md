# Hydra — Agent Contract

Audience: Claude. Hydra intercepts secrets, OWASP vulnerabilities, dangerous commands, poisoned configs, and phantom dependencies — at write-time and before Bash executes, not after. Every rule is anchored in a real CVE, incident, or research paper.

## Shared behavioral modules

These apply to every skill in every plugin. Load once; do not re-derive.

- @../vis/packages/core/conduct/discipline.md — coding conduct: think-first, simplicity, surgical edits, goal-driven loops
- @../vis/packages/core/conduct/capability-fidelity.md — contracts survive capability gaps: recover, escalate, or abort; never silently substitute
- @../vis/packages/core/conduct/context.md — attention-budget hygiene, U-curve placement, checkpoint protocol
- @../vis/packages/core/conduct/verification.md — independent checks, baseline snapshots, dry-run for destructive ops
- @../vis/packages/core/conduct/verdict-calibration.md — every verdict (DEPLOY/PASS/COMPLETE/VERIFIED) carries n, sampling method, and a calibration qualifier; vis-side abstraction over the wixie DEPLOY bar
- @../vis/packages/core/conduct/doubt-engine.md — adversarial self-check before agreement; four-step pass against F01 sycophancy
- @../vis/packages/core/conduct/delegation.md — subagent contracts, tool whitelisting, parallel vs. serial rules
- @../vis/packages/core/conduct/failure-modes.md — 14-code taxonomy for accumulated-learning logs
- @../vis/packages/core/conduct/tool-use.md — tool-choice hygiene, error payload contract, parallel-dispatch rules
- @../vis/packages/skills/conduct/skill-authoring.md — SKILL.md frontmatter discipline, discovery test
- @../vis/packages/core/conduct/hooks.md — advisory-only hooks, injection over denial, fail-open
- @../vis/packages/core/conduct/metacognition.md — periodic goal-restate; fires every K=8 tool-uses or on user meta-question
- @../vis/packages/core/conduct/precedent.md — log self-observed failures to `state/precedent-log.md`; consult before risky steps
- @../vis/packages/core/conduct/precedent-freshness.md — verify self-authored memory/precedent/briefings before relying on them: Class-A surfaces (path/function/flag) get a Glob/Grep existence check; Class-B snapshots get a git-log freshness check; Class-C feedback rules are trusted unless contradicted
- @../vis/packages/core/conduct/prior-art-discovery.md — F28 counter: run the 5-target discovery pass (shared/scripts, packages/*/skills, state/proposals, slug-glob, signature-grep) before authoring a new tool/script/skill/module
- @../vis/packages/core/conduct/reversibility-foresight.md — classify action reversibility (trivial/costly/impossible) before acting; confirmation scales with tier
- @../vis/packages/core/conduct/substrate-consumption.md — read-side complement to precedent.md: consume briefing, MEMORY, learnings, and precedent before acting; counter to F24 substrate-blindness
- @../vis/packages/core/conduct/sunk-cost-iteration.md — stop-and-re-ask after 2 INCONCLUSIVE/BLOCKED results on the same artifact; iteration is not an authorization to keep patching
- @../vis/packages/core/conduct/tier-sizing.md — prompt verbosity scales inversely with model tier; Haiku needs mechanical steps, Opus runs on intent
- @../vis/packages/web/conduct/web-fetch.md — external URL handling: cache, dedup, budget; WebFetch is Haiku-tier-only
- @../vis/packages/web/conduct/research-pipeline.md — multi-phase web research discipline: 6-phase shape, work-budget floors, mandatory adversarial round, 15-min wall-clock floor
- @../vis/packages/web/conduct/source-discipline.md — handling web-fetched evidence: untrusted-source quote wrapping, independence checks, τ, dissemination_score, source-type weighting
- @../vis/packages/web/conduct/citation-verification.md — trace + re-fetch protocol; Wayback Machine fallback; 4-class support taxonomy (Supported / Partial / Unsupported / Uncertain); refetch_pass_rate thresholds

When a module conflicts with a plugin-local instruction, the plugin wins — but log the override.

## Lifecycle

The 5 scanner plugins (table below) carry agents and drive the per-write detection lifecycle. The other 10 functional plugins (package-gate, egress-monitor, canary, capability-fence, license-gate, sbom-emitter, capability-shield, egress-shield, reach-filter, state-integrity) are agentless — they run as advisory hooks, opt-in blockers, or skill-invoked compliance tools. See `README.md § 15 Plugins, 5 Agents, 2,039 Patterns` for the full plugin matrix.

| Plugin | Hook | Purpose |
|--------|------|---------|
| config-shield | SessionStart | Scan repo configs for CVE-matched attack signatures (R5) |
| action-guard | PreToolUse (Bash) | **Block** dangerous commands (exit 2); subcommand-overflow check (R4, R7) |
| secret-scanner | PostToolUse (Write\|Edit\|MultiEdit) | 319 patterns + Shannon entropy (R1, R2) |
| vuln-detector | PostToolUse (Write\|Edit\|MultiEdit) | OWASP Top 10 / CWE map, 156 patterns (R3) |
| audit-trail | PostToolUse (all tools) | JSONL log + EMA posture (R8) |

## Algorithms

R1 Aho-Corasick Pattern Engine · R2 Shannon Entropy Analysis · R3 OWASP Vulnerability Graph · R4 Markov Action Classification · R5 Config Poisoning Detection · R6 Phantom Dependency Detection · R7 Subcommand Overflow · R8 EMA Posture Decay. Derivations: `docs/science/README.md`.

Pattern databases: **20 files, 2,039 patterns, 98 CWEs.** Original 5 (secrets 319, vulns 156, dangerous-ops 113, config-attacks 122, slopsquatting 199) + 15 new databases: cicd-attacks 130, container-security 113, iac-misconfig 120, crypto-weakness 90, auth-bypass 80, ssrf-patterns 61, api-security 81, ai-agent-attacks 116, regex-dos 44, deserialization 69, file-operations 50, logging-forgery 41, prototype-pollution 35, dependency-confusion 50, header-security 50.

## Behavioral contracts

Markers: **[H]** hook-enforced · **[A]** advisory.

1. **[H] IMPORTANT — Acknowledge every `[Hydra]` stderr.** Name the category (secret / vuln / command / config / phantom dep) and the severity. Do not paraphrase it away.
2. **[H] YOU MUST NOT bypass a BLOCKED command.** action-guard returns exit 2 — the command did not execute. Do not retry with subcommand splitting, base64, shell substitution, or `eval` wrappers. R7 specifically catches those evasions. Explain the block and suggest a safe alternative.
3. **[H] YOU MUST NOT log full secret values.** Anywhere. stderr, chat, logs, reports, commits. Only the masked form (`first4...last4`) via `shared/sanitize.sh::mask_secret()`. This is enforced at the hook layer; defeating it is a contract violation.
4. **[A] STOP on CRITICAL.** Tell the developer: "Hydra found a critical security issue. Here's what happened and what we should do." Do not continue the task until acknowledged.
5. **[A] Verify phantom deps (R6).** If a new import is flagged as phantom/typosquat, do not install. 20% of AI-suggested packages don't exist (USENIX 2025); attackers register them. Verify the package on its registry and confirm ownership first.
6. **[A] Honour config-shield at SessionStart.** If a config file was flagged (CVE-2025-59536, -21852, -54135, -54794), do not edit around it or silence it. Surface and ask.
7. **[A] ESCALATE in strict mode.** If `plugins/action-guard/state/config.json` is `strict`, treat every WARN as BLOCK. In permissive, still surface findings — do not pretend they don't exist because the hook let them through.

## Severity response

| Severity | Trigger | Action |
|----------|---------|--------|
| CRITICAL | Active threat (exposed secret, dangerous cmd, malicious config) | STOP; surface immediately |
| HIGH | API keys, OWASP vulns with CWE | Pause; explain |
| MEDIUM | Weak patterns, CORS wildcards, typosquat suspicion | Mention to developer |
| LOW | Minor concern | Note if relevant |
| INFO | Test fixtures, known examples, in-comment matches | Acknowledge only if asked |

Test files (`test|spec|fixture|mock|example` in path) and `false_positive_hints` from pattern definitions auto-reduce severity. `AKIAIOSFODNN7EXAMPLE` in a test file = INFO, not CRITICAL.

## Strictness modes

| Mode | Block patterns | Warn patterns |
|------|---------------|---------------|
| strict | BLOCK | BLOCK |
| balanced (default) | BLOCK | WARN (stderr) |
| permissive | WARN | WARN |

Mode lives in `plugins/action-guard/state/config.json`.

## State paths

```
plugins/audit-trail/state/audit.jsonl        (append-only, 10MB rotation)
plugins/secret-scanner/state/audit.jsonl     (masked values only)
plugins/action-guard/state/audit.jsonl       (blocked/warned cmds)
plugins/action-guard/state/config.json       (mutable, mode)
/tmp/hydra-report.html                       (generated report)
```

## Agent tiers

All 5 agents in `./plugins/*/agents/*.md` with explicit output contracts. Tiers follow the @enchanter-ai convention (Orchestrator/Opus, Executor/Sonnet, Validator/Haiku):

- `scanner` (Haiku) · `chronicler` (Haiku) — validators
- `guardian`, `inspector`, `analyzer` (Sonnet) — executors (CWE disambiguation and config-attack assessment need real reasoning)

## Anti-patterns

- **Command-block evasion.** Splitting `rm -rf /` across subcommands, base64-encoding, piping through `eval`, or wrapping in `bash -c`. R7 blocks >50 subcommand separators before pattern match; the evasion adds risk without benefit.
- **Unmasked secret in any output.** Including stderr, chat, reports, commit messages. GitGuardian 2026: Claude-assisted commits leak at 3.2× baseline — the masking contract is the mitigation.
- **Phantom install.** Installing a typosquat or hallucinated package to "unblock" a task. R6 catches edit-distance ≤ 2 typosquats and 199 known hallucinated names across npm / PyPI / Cargo / Go / RubyGems.
- **Config-shield silence.** Editing around a flagged `.claude/settings.json`, `.vscode/tasks.json`, or `.mcp.json` without surfacing. Hook-on-clone is a real attack class (Check Point CVE-2025-59536).
- **State mutation.** Editing `audit.jsonl` or `config.json` to dismiss findings or flip strictness without the developer's say-so. Breaks R8 posture tracking and the strict-mode contract.
