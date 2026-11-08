#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp)"
cat > "$tmp"

cmd="$(jq -r '.tool_input.command // ""' "$tmp")"

deny_regex='(^|[[:space:]])(sudo|rm -rf|terraform apply|kubectl apply|kubectl delete|helm upgrade|aws secretsmanager)\b'

if [[ "$cmd" =~ $deny_regex ]]; then
  jq -n --arg reason "Blocked dangerous command: $cmd" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
fi

# Block background rg processes — a primary cause of OOM events (2026-11-07).
# Agents must not spawn unbounded parallel searches via &.
if [[ "$cmd" =~ (^|[[:space:]])rg[[:space:]] ]] && [[ "$cmd" =~ [[:space:]]'&'([[:space:]]|$) ]]; then
  jq -n --arg reason "Blocked: background rg search ('rg ... &') is prohibited. Run searches sequentially. See docs/ai/AI_DEVELOPMENT_RESOURCE_SAFETY.md." '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
fi

# Warn when active rg process count is high — do not block legitimate work,
# but surface pressure so the agent can self-throttle.
rg_count=$(pgrep -c '^rg$' 2>/dev/null || echo 0)
if [ "${rg_count:-0}" -ge 20 ]; then
  jq -n --arg count "$rg_count" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: ("Resource pressure: " + $count + " active rg processes. Stop issuing new searches — see docs/ai/AI_DEVELOPMENT_RESOURCE_SAFETY.md section A.")
    }
  }'
  exit 0
fi

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    permissionDecisionReason: "Allowed by repo command guard"
  }
}'
