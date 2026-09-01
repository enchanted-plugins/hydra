# Getting started with Hydra

Hydra is defense-in-depth for AI-assisted development: config scanning at session start, action gating before dangerous commands, secret + vulnerability detection on every tool call, and an audit trail for forensic review. Zero runtime dependencies — bash + jq only. This page gets you from zero to a first scan in under 5 minutes.

## 1. Install (60 seconds)

```
/plugin marketplace add enchanter-ai/hydra
/plugin install full@hydra
/plugin list
```

You should see five Hydra sub-plugins including `config-shield`, `action-guard`, `secret-scanner`, `vuln-detector`, and `audit-trail`. If any are missing, see [installation.md](installation.md).

## 2. Verify the hooks registered

Start a new Claude Code session. Hydra's `config-shield` fires on session start and scans your repo for repo-level attack vectors: poisoned `.claude/` configs, unexpected hook declarations, suspicious MCP servers.

If nothing fires, see [troubleshooting.md](troubleshooting.md) § Hooks don't fire.

## 3. Run an explicit config check

```
/config-check
```

Runs the full config scan on-demand. Output shows pattern matches across 2,039 patterns covering 98 CWEs, organized by severity.

## 4. Scan for secrets

```
/secrets
```

The `secret-scanner` post-tool hook runs automatically on every Write / Edit. To scan the current working tree manually:

```
/secrets --scan-tree
```

Aho-Corasick pattern matching + entropy scoring. High-entropy strings in newly-written files are flagged even if they don't match a known pattern.

## 5. See action-guard in action

Ask Claude to run a dangerous command (`rm -rf`, `git reset --hard`, `DROP TABLE`, etc.). The `action-guard` PreToolUse hook intercepts and emits an advisory warning with the matched risk class. The hook is advisory — see [../vis/packages/core/conduct/hooks.md](../../vis/packages/core/conduct/hooks.md) § Injection over denial — so you can still proceed, but you've been warned.

## 6. Scan for vulnerabilities

```
/vulns
```

Runs the OWASP + CWE pattern library against the working tree. Output includes severity, pattern ID, line reference, and suggested remediation.

## 7. Review the audit trail

```
/audit
```

`audit-trail` logs every security-relevant event (config match, secret flag, vuln detection, action gate) with timestamp, context, and verdict. Use it for forensics or compliance reporting.

## Safety diagnostics

```
/safety
```

Self-test: every pattern source loads, jq is present, the audit trail is writable. Run this after any settings change.

## Next steps

- [docs/science/README.md](science/README.md) — Aho-Corasick, entropy, OWASP coverage, action classifier, config scanner, phantom detector, overflow guard, threat modeler — derived.
- [docs/architecture/](architecture/) — auto-generated diagram.
- [SECURITY.md](../SECURITY.md) — how to report security issues in Hydra itself.

Broken first run? → [troubleshooting.md](troubleshooting.md).
