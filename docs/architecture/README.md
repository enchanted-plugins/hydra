# Hydra Architecture

> Auto-generated from codebase by `generate.py`. Run `python docs/architecture/generate.py` to regenerate.

## Interactive Explorer

Open [index.html](index.html) in a browser to explore the architecture interactively with tabbed Mermaid diagrams and plugin component cards.

## At a Glance

**5 plugins. 5 agents. 2,039 patterns. 20 databases. 98 CWEs. 8 algorithms. 35 tests.**

## Diagrams

| Diagram | File | Description |
|---------|------|-------------|
| High Level | [highlevel.mmd](highlevel.mmd) | 5 plugins connected to Claude Code with hook phases |
| Session Lifecycle | [lifecycle.mmd](lifecycle.mmd) | SessionStart → PreToolUse → Execute → PostToolUse cycle |
| Data Flow | [dataflow.mmd](dataflow.mmd) | Data flow from tools through hooks to audit.jsonl |
| Hook Bindings | [hooks.mmd](hooks.mmd) | Hook binding map with matchers and timeouts per plugin |

## Plugin Summary

| Plugin | Hook Phase | Matcher | Timeout | Algorithms |
|--------|-----------|---------|---------|------------|
| config-shield | SessionStart | — | 30s | R5 |
| action-guard | PreToolUse | Bash | 10s | R4, R7 |
| secret-scanner | PostToolUse | Write/Edit | 15s | R1, R2 |
| vuln-detector | PostToolUse | Write/Edit | 15s | R3 |
| audit-trail | PostToolUse | All | 10s | R8 |

## Pattern Databases (20 files, 2,039 patterns)

### Original 5 Databases (909 patterns)

| Database | Patterns | Coverage |
|----------|----------|----------|
| secrets.json | 319 | API keys, tokens, private keys, connection strings — 80+ providers |
| vulns.json | 156 | OWASP Top 10 — SQL injection, XSS, path traversal, command injection |
| dangerous-ops.json | 113 | Destructive commands — rm -rf, DROP TABLE, force push, reverse shells |
| config-attacks.json | 122 | Malicious repo configs — .claude hooks, .vscode autorun, .npmrc hijack |
| slopsquatting.json | 199 | AI-hallucinated packages + typosquats across 5 ecosystems |

### New 15 Databases (1,130 patterns)

| Database | Patterns | Attack Surface |
|----------|----------|----------------|
| cicd-attacks.json | 130 | GitHub Actions injection, GitLab CI, Jenkins, CircleCI, Azure DevOps |
| container-security.json | 113 | Dockerfile, Kubernetes, Helm, docker-compose misconfigurations |
| iac-misconfig.json | 120 | Terraform, CloudFormation, ARM templates, Pulumi |
| crypto-weakness.json | 90 | Weak hashes, broken ciphers, ECB mode, TLS misconfig, timing attacks |
| auth-bypass.json | 80 | JWT, session, CSRF, OAuth, cookies, IDOR, mass assignment |
| ssrf-patterns.json | 61 | Cloud metadata, localhost bypass, URL scheme abuse, webhooks |
| api-security.json | 81 | GraphQL, REST, rate limiting, CORS, WebSocket, gRPC |
| ai-agent-attacks.json | 116 | Prompt injection, MCP poisoning, jailbreaks, rules backdoors |
| regex-dos.json | 44 | Nested quantifiers, overlapping alternation, user-created regex |
| deserialization.json | 69 | Java, Python, PHP, Ruby, .NET, Node.js, Go deserialization |
| file-operations.json | 50 | Path traversal, zip slip, TOCTOU, upload, archive, LFI/RFI |
| logging-forgery.json | 41 | Log4Shell, CRLF injection, sensitive data in logs |
| prototype-pollution.json | 35 | __proto__ assignment, lodash.merge, JSON.parse pollution |
| dependency-confusion.json | 50 | Install scripts, lockfile poisoning, protestware, typosquatting |
| header-security.json | 50 | CSP, HSTS, CORS headers, server exposure, cookie security |

## Execution Order

```
1. Session Start  → config-shield scans repo configs (122 signatures)
2. Bash call      → action-guard classifies → BLOCK or ALLOW (113 patterns)
3. Write/Edit     → secret-scanner (319 patterns) + vuln-detector (1,286 patterns across 16 databases) scan content
4. Any tool       → audit-trail logs event + updates EMA posture
```

## Test Coverage

35 tests across all plugins + shared utilities:

```
tests/
├── action-guard/     7 tests (safe allow, rm-rf block, curl|bash, reverse shell, DROP TABLE, subcommand overflow, force push warn)
├── config-shield/    5 tests (claude hooks, clean repo, npmrc hijack, postinstall, vscode autorun)
├── secret-scanner/   7 tests (anthropic key, connection string, github token, clean file, private key, test downgrade, write hook)
├── vuln-detector/    6 tests (clean, command injection, deserialization, hardcoded creds, SQL injection, XSS)
├── audit-trail/      2 tests (event logging, log rotation)
├── shared/           8 tests (mask secret, sanitize path, pattern validity, schema, unique IDs, counts, CWE coverage, regex)
└── run-all.sh        Master runner
```
