#!/usr/bin/env bash
# Test: action-guard — force-push to a feature branch warns (not deny/ask) (HYDRA_ENFORCE=enforce, JSON permissionDecision mechanism)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HYDRA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOOK="$HYDRA_ROOT/plugins/action-guard/hooks/pre-tool-use/guard-action.sh"
export CLAUDE_PLUGIN_ROOT="$HYDRA_ROOT/plugins/action-guard"
TRANSCRIPT=$(mktemp); echo test > "$TRANSCRIPT"
CMD="git push --force origin feature-branch"
INPUT=$(jq -cn --arg tool "Bash" --arg cmd "$CMD" --arg t "$TRANSCRIPT" '{tool_name:$tool, tool_input:{command:$cmd}, transcript_path:$t}')
ERRF=$(mktemp)
OUT=$(printf "%s" "$INPUT" | HYDRA_ENFORCE=enforce bash "$HOOK" 2>"$ERRF")
ERR=$(cat "$ERRF")
rm -f "$TRANSCRIPT" "$ERRF"
DEC=$(printf "%s" "$OUT" | jq -r '.hookSpecificOutput.permissionDecision // "none"' 2>/dev/null || echo none)
[ -z "$DEC" ] && DEC="none"
if [[ "$DEC" != "none" ]]; then echo "FAIL: warn tier must not emit a decision, got '$DEC'"; exit 1; fi
if ! echo "$ERR" | grep -qi "advisory\|warning"; then echo "FAIL: expected an advisory on stderr"; exit 1; fi
echo "PASS: force-push to a feature branch warns (not deny/ask)"; exit 0
