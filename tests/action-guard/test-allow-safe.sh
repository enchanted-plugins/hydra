#!/usr/bin/env bash
# Test: action-guard — safe command is allowed (HYDRA_ENFORCE=enforce, JSON permissionDecision mechanism)
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HYDRA_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOOK="$HYDRA_ROOT/plugins/action-guard/hooks/pre-tool-use/guard-action.sh"
export CLAUDE_PLUGIN_ROOT="$HYDRA_ROOT/plugins/action-guard"
TRANSCRIPT=$(mktemp); echo test > "$TRANSCRIPT"
CMD="ls -la"
INPUT=$(jq -cn --arg tool "Bash" --arg cmd "$CMD" --arg t "$TRANSCRIPT" '{tool_name:$tool, tool_input:{command:$cmd}, transcript_path:$t}')
ERRF=$(mktemp)
OUT=$(printf "%s" "$INPUT" | HYDRA_ENFORCE=enforce bash "$HOOK" 2>"$ERRF")
ERR=$(cat "$ERRF")
rm -f "$TRANSCRIPT" "$ERRF"
DEC=$(printf "%s" "$OUT" | jq -r '.hookSpecificOutput.permissionDecision // "none"' 2>/dev/null || echo none)
[ -z "$DEC" ] && DEC="none"
if [[ "$DEC" != "none" ]]; then echo "FAIL: safe command must not be denied/asked, got '$DEC'"; exit 1; fi
echo "PASS: safe command is allowed"; exit 0
