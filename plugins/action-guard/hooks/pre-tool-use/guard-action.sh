#!/usr/bin/env bash
# action-guard: PreToolUse hook (VF-05 fail-closed rebuild)
# ---------------------------------------------------------------------------
# Classifies Bash commands into three enforcement tiers and, depending on the
# rollout switch, either logs a shadow event (default, blocks nothing) or emits
# a Claude Code PreToolUse permissionDecision that actually blocks/prompts.
#
# Tiers (per-rule `enforcement` field in shared/patterns/dangerous-ops.json):
#   deny  — catastrophic/irreversible ONLY (floor pinned by policy.json)
#   ask   — costly-but-legitimate infra ops (prompt the human)
#   warn  — everything else (stderr advisory, never blocks)
#
# Rollout switch — HYDRA_ENFORCE:
#   unset | "shadow" (DEFAULT) — classify + log would_deny/would_ask/would_warn
#                                to state/audit.jsonl; emit NO permissionDecision;
#                                exit 0. Blocks NOTHING. Safe first ship.
#   "enforce"                  — deny -> permissionDecision "deny"     (exit 0)
#                                ask  -> permissionDecision "ask"      (exit 0)
#                                warn -> stderr advisory + exit 0
#
# Mechanism = Claude Code PreToolUse JSON permissionDecision on stdout + exit 0
# (confirmed against https://code.claude.com/docs/en/hooks.md). Valid decisions
# are "allow" | "deny" | "ask" (per Claude Code hooks docs). The ask tier maps
# to "ask", which prompts the user to confirm.
#
# Anti-tamper: the deny tier is pinned by the git-TRACKED policy.json, never by
# the agent-writable (gitignored) state/config.json. config.json may only RAISE
# strictness (promote_to_ask / promote_to_deny); it can never lower the deny
# floor. The old "mode: permissive == bypass" path is gone.
#
# Matching is delegated to scripts/classify.py — a single Python process using
# the real `re` engine. The dangerous-ops patterns are PCRE ((?:...), (?!...),
# \d, \b); the previous `grep -E` loop could not parse those and silently never
# matched them (a fail-open hole). Python re fixes that and is far faster than
# ~340 forked subprocesses per call.
# ---------------------------------------------------------------------------

# Subagent recursion guard — see shared/conduct/hooks.md
if [[ -n "${CLAUDE_SUBAGENT:-}" ]]; then exit 0; fi

# Fail-open on unexpected internal error (a crashing hook must not wedge every
# Bash call). The deliberate block path clears this trap before emitting.
trap 'exit 0' ERR INT TERM

set -uo pipefail

# ── Dependencies (fail-open if missing) ──
if ! command -v jq >/dev/null 2>&1; then exit 0; fi
PYTHON_BIN=""
if command -v python >/dev/null 2>&1; then PYTHON_BIN="python"
elif command -v python3 >/dev/null 2>&1; then PYTHON_BIN="python3"
else exit 0; fi

# ── Resolve paths ──
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
SHARED_DIR="${PLUGIN_ROOT}/../../shared"

# shellcheck source=../../../../shared/constants.sh
source "${SHARED_DIR}/constants.sh"
# shellcheck source=../../../../shared/sanitize.sh
source "${SHARED_DIR}/sanitize.sh"
# shellcheck source=../../../../shared/metrics.sh
source "${SHARED_DIR}/metrics.sh"
# shellcheck source=../../../../shared/compat.sh
source "${SHARED_DIR}/compat.sh"

STATE_DIR="${PLUGIN_ROOT}/state"
POLICY_FILE="${PLUGIN_ROOT}/policy.json"
CONFIG_FILE="${STATE_DIR}/config.json"
CLASSIFY="${PLUGIN_ROOT}/scripts/classify.py"
PATTERNS_FILE="${SHARED_DIR}/${HYDRA_PATTERNS_DANGEROUS}"

if [[ ! -f "$CLASSIFY" || ! -f "$PATTERNS_FILE" ]]; then exit 0; fi

# ── Rollout switch ──
ENFORCE_MODE="shadow"
case "${HYDRA_ENFORCE:-}" in
  enforce)   ENFORCE_MODE="enforce" ;;
  ""|shadow) ENFORCE_MODE="shadow" ;;
  *)         ENFORCE_MODE="shadow" ;;   # unknown value -> safe default
esac

# ── Read hook input from stdin (capped at 1MB) ──
HOOK_INPUT=$(hydra_read_stdin 1048576)
if ! validate_json "$HOOK_INPUT"; then exit 0; fi
COMMAND=$(printf "%s" "$HOOK_INPUT" | jq -r '.tool_input.command // ""' 2>/dev/null)
if [[ -z "$COMMAND" ]]; then exit 0; fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Detect (and refuse to honor) any config strictness-LOWERING attempt ──
# config.json may only raise strictness. A lowering attempt is ignored by the
# classifier; we record it here for the audit trail.
CONFIG_LOWER_ATTEMPT="false"
if [[ -f "$CONFIG_FILE" ]] && jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
  LEGACY_MODE=$(jq -r '.mode // ""' "$CONFIG_FILE" 2>/dev/null)
  HAS_LOWER=$(jq -r 'has("disable") or has("allow") or has("demote_to_warn")' "$CONFIG_FILE" 2>/dev/null)
  if [[ "$LEGACY_MODE" == "permissive" || "$HAS_LOWER" == "true" ]]; then
    CONFIG_LOWER_ATTEMPT="true"
  fi
fi

# ── Classify (single Python process; real PCRE engine) ──
CLASSIFY_OUT=$(printf "%s" "$COMMAND" | "$PYTHON_BIN" "$CLASSIFY" \
  --dangerous "$PATTERNS_FILE" \
  --policy "$POLICY_FILE" \
  --config "$CONFIG_FILE" \
  --limit "$HYDRA_SUBCOMMAND_LIMIT" 2>/dev/null)

# No match -> allow silently
if [[ -z "$CLASSIFY_OUT" ]]; then exit 0; fi

IFS=$'\t' read -r TOP_TIER TOP_OP_ID TOP_REASON <<< "$CLASSIFY_OUT"
[[ -z "$TOP_TIER" ]] && exit 0

# ── Audit + emit helpers ──
emit_audit() {
  # $1 = event name
  local entry
  entry=$(jq -cn \
    --arg event "$1" \
    --arg ts "$TIMESTAMP" \
    --arg tier "$TOP_TIER" \
    --arg op_id "$TOP_OP_ID" \
    --arg reason "$TOP_REASON" \
    --arg enforce "$ENFORCE_MODE" \
    --arg lower_attempt "$CONFIG_LOWER_ATTEMPT" \
    '{event:$event, ts:$ts, tier:$tier, op_id:$op_id, reason:$reason, enforce_mode:$enforce, config_lower_attempt:$lower_attempt}')
  log_metric "${STATE_DIR}/audit.jsonl" "$entry"
}

emit_permission_decision() {
  # $1 = permissionDecision (deny|ask)
  jq -cn \
    --arg decision "$1" \
    --arg reason "action-guard: ${TOP_REASON} [${TOP_OP_ID}]" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse", permissionDecision:$decision, permissionDecisionReason:$reason}}'
}

if [[ "$ENFORCE_MODE" == "shadow" ]]; then
  # ── SHADOW: log, advise on stderr, block nothing ──
  case "$TOP_TIER" in
    deny) emit_audit "would_deny" ;;
    ask)  emit_audit "would_ask" ;;
    warn) emit_audit "would_warn" ;;
    *)    exit 0 ;;
  esac
  {
    echo "=== action-guard (shadow) ==="
    printf "would_%s: %s [%s]\n" "$TOP_TIER" "$TOP_REASON" "$TOP_OP_ID"
    echo "Shadow mode blocks nothing. Set HYDRA_ENFORCE=enforce after reviewing state/audit.jsonl."
  } >&2
  trap - ERR INT TERM
  exit 0
fi

# ── ENFORCE ──
case "$TOP_TIER" in
  deny)
    emit_audit "action_denied"
    emit_permission_decision "deny"
    ;;
  ask)
    emit_audit "action_asked"
    emit_permission_decision "ask"
    ;;
  warn)
    emit_audit "action_warned"
    {
      echo "=== action-guard (advisory) ==="
      printf "WARNING: %s [%s]\n" "$TOP_REASON" "$TOP_OP_ID"
      echo "Advisory only — execution proceeds. Review if unintended."
    } >&2
    ;;
  *)
    exit 0
    ;;
esac

trap - ERR INT TERM
exit 0
