# Coverage contract — what a Hydra scan result actually means

Audience: anyone consuming `vuln-scanner.py` output, human or agent.

## The law

> **ZERO FINDINGS + INCOMPLETE COVERAGE MUST NEVER MEAN CLEAN.**

The scanner reports **coverage** alongside **findings**. Branch on `clean`,
never on `len(findings) == 0`.

## Why this exists

`vuln-scanner.py` used to print a bare `[]` for four different situations:

| situation | old result | new status |
|---|---|---|
| analysed fully, nothing found | `[]` | `partial` (see below) |
| only the first 2000 lines analysed | `[]` | `degraded`, `truncated: true` |
| no rules exist for this extension | `[]` | `unsupported` |
| pattern corpus unreadable | `[]` | `unavailable` |

Measured: a Go file whose command injection sits at line 2103 scanned as `[]`
with no signal that 103 lines were never read. A `.c` file with a hardcoded
password and a `system(argv[1])` call also scanned as `[]`, because C is not
in the extension map at all.

## What this scanner is, and is not

It is a **single-line regex prefilter**. It is not a dataflow engine and must
not be presented as one. A class analysed by this engine is therefore reported
as `partial` at best — never `complete` — because it cannot follow taint
across lines or functions.

Declared blind shapes, enumerated in every coverage entry:

`argv` · `environment` · `config-file` · `stdin` · `function-parameter` ·
`cross-line` · `cross-function`

Some rules are additionally **shape-bound**: `command-injection-go` and
`path-traversal-go` only fire when an HTTP taint token (`r.URL`, `r.Form`,
`r.Header.Get`, `mux.Vars`, `c.Param`, `c.Query`) appears on the same line as
the sink. They are written for web handlers. On a CLI or agent runtime whose
taint arrives from a JSON config file, they cannot fire — this is by
construction, not a tuning problem, and multiplying regex combinations is not
the fix. Shape-boundness is derived by inspecting each regex, so the coverage
claim cannot drift away from the corpus.

## Language fidelity

A rule tagged `"language": ["go"]` is claiming it can detect that defect in
Go. Measured against idiomatic vulnerable Go, only **8 of 19** Go-tagged rules
fired on their own stated intent:

- `weak-hash-md5` / `weak-hash-sha1` matched `hashlib.md5`, `MD5.Create`,
  `MessageDigest` and `crypto.createHash` — Python, C#, Java and JS forms,
  never Go's `md5.Sum` / `sha1.New`
- credential rules required `password = "..."`, so Go's `:=` form evaded them
- `insecure-random-go` matched only the import string `math/rand`, never a
  call site such as `rand.Intn`

After repair: **17 of 19**, with zero false positives across 12 safe idiomatic
lookalikes. `tests/shared/test-corpus-language-fidelity.py` makes this class
of drift impossible to reintroduce — every rule tagged for a language must
match a real vulnerable line for it or be listed as `taint_bound` with a
reason.

## Reading the output

```json
{
  "schema": "enchanter.analysis-report/v1",
  "analysis_status": "partial | degraded | unsupported | unavailable | complete",
  "truncated": false,
  "false_clean_risk": true,
  "clean": false,
  "coverage": [ { "class": "injection", "status": "partial",
                  "shapes_unsupported": ["config-file", "argv", "..."] } ],
  "findings": []
}
```

`--findings-only` restores the legacy bare-array output for existing
consumers. That shape cannot express coverage, so anything reading it must not
treat an empty array as assurance.

## Scope note

This document covers Hydra's **code-analysis** surface only. Hydra's design
centre is its runtime guardrail plugins (secret-scanner, action-guard,
config-shield, egress, package-gate). Those are a different product surface
and nothing here evaluates them.

## Known gap

The `vuln-detector` PostToolUse hook (`detect-vuln.sh`) is a **separate
implementation** with its own inline matching, and does not call
`vuln-scanner.py`. It therefore does not yet emit coverage. Repairing the
scanner did not repair the hook.
