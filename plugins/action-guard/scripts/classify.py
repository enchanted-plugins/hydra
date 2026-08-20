#!/usr/bin/env python3
"""
classify.py — action-guard command classifier (VF-05).

Single-process replacement for the old per-rule `grep -qE` loop. Two reasons:

  1. CORRECTNESS. The dangerous-ops.json patterns are PCRE — they use (?:...),
     (?!...), \\d, \\b, \\s. `grep -E` (ERE) cannot parse those constructs, so
     every rule using them silently never matched (a fail-open hole). Python's
     `re` engine handles them natively.
  2. SPEED. One Python process per hook call instead of ~340 forked
     grep/sed subprocesses — critical for a PreToolUse hook on Windows/Git-Bash.

Reads the raw Bash command from stdin. Prints ONE line to stdout when a rule (or
the subcommand-overflow heuristic) matches:

    <tier>\t<op_id>\t<reason>

where tier is deny | ask | warn (strictest match wins). Prints nothing when
nothing matches. Exit 0 on success, 2 on internal error (the hook fails open).

Tier resolution:
  base tier   = the rule's `enforcement` field (deny/ask/warn)
  RAISED by   = policy.json `deny` list (committed floor — cannot be lowered)
  RAISED by   = config.json `promote_to_deny` / `promote_to_ask` (raise-only)
config.json can NEVER lower a tier; a lowering attempt (mode:permissive, etc.)
is ignored here and flagged by the hook for audit.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_TIER_RANK = {"deny": 3, "ask": 2, "warn": 1}

# Interpreter / DB-client / shell -c tokens. When present, quoted text is not
# inert data (it will be executed), so we also match the ORIGINAL command.
_INTERP_RE = re.compile(
    r"(^|[\s|;&(])(sudo\s+)?"
    r"(bash|sh|zsh|ksh|dash|psql|mysql|mysqladmin|mongo|mongosh|redis-cli|"
    r"sqlite3|etcdctl|python3?|python2|perl|ruby|node|php|eval|exec|xargs|env)"
    r"(\s|$)"
)

_DQ_RE = re.compile(r'"[^"]*"')
_SQ_RE = re.compile(r"'[^']*'")
_COMMENT_RE = re.compile(r"(^|\s)#.*$")


def strip_quotes_and_comments(cmd: str) -> str:
    """Blank single/double-quoted substrings, then strip a trailing # comment.

    Quotes are blanked first so a `#` inside a string is not treated as a
    comment. Matches decision 5 of the VF-05 locked design.
    """
    s = _DQ_RE.sub(" ", cmd)
    s = _SQ_RE.sub(" ", s)
    s = _COMMENT_RE.sub(" ", s)
    return s


def _load_json(path: str | None) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _count_parts(stripped: str) -> int:
    parts = 1
    parts += stripped.count(";")
    parts += stripped.count("|")
    parts += stripped.count("&&")
    return parts


def main() -> int:
    ap = argparse.ArgumentParser(prog="classify.py")
    ap.add_argument("--dangerous", required=True)
    ap.add_argument("--policy", default=None)
    ap.add_argument("--config", default=None)
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    command = sys.stdin.read()
    if not command.strip():
        return 0

    stripped = strip_quotes_and_comments(command)
    interp = bool(_INTERP_RE.search(stripped))

    try:
        rules = json.loads(Path(args.dangerous).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"classify: cannot read dangerous-ops: {e}\n")
        return 2

    policy = _load_json(args.policy)
    config = _load_json(args.config)
    policy_deny = set(policy.get("deny", []) or [])
    promote_deny = set(config.get("promote_to_deny", []) or [])
    promote_ask = set(config.get("promote_to_ask", []) or [])

    top_tier = ""
    top_rank = 0
    top_op = ""
    top_reason = ""

    def consider(tier: str, op_id: str, reason: str) -> None:
        nonlocal top_tier, top_rank, top_op, top_reason
        r = _TIER_RANK.get(tier, 0)
        if r > top_rank:
            top_rank, top_tier, top_op, top_reason = r, tier, op_id, reason

    # R7: subcommand overflow -> deny heuristic
    if _count_parts(stripped) > args.limit:
        n = _count_parts(stripped)
        consider(
            "deny",
            "subcommand-overflow",
            f"Command has {n} subcommands (limit {args.limit}) — "
            "matches the Adversa AI deny-rule bypass pattern.",
        )

    # R4: pattern classification
    for rule in rules:
        pat = rule.get("pattern")
        if not pat:
            continue
        try:
            rx = re.compile(pat)
        except re.error:
            continue  # skip an unparseable rule rather than crash
        matched = bool(rx.search(stripped))
        if not matched and interp:
            matched = bool(rx.search(command))
        if not matched:
            continue

        tier = rule.get("enforcement", "warn")
        if tier not in _TIER_RANK:
            tier = "warn"
        op_id = rule.get("id", "")
        if op_id in policy_deny:
            tier = "deny"
        if op_id in promote_deny:
            tier = "deny"
        if op_id in promote_ask and tier == "warn":
            tier = "ask"
        consider(tier, op_id, rule.get("description", ""))

    if top_tier:
        reason = top_reason.replace("\t", " ").replace("\n", " ").strip()
        sys.stdout.write(f"{top_tier}\t{top_op}\t{reason}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"classify: fatal: {e}\n")
        sys.exit(2)
