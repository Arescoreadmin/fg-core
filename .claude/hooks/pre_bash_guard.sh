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

jq -n '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    permissionDecisionReason: "Allowed by repo command guard"
  }
}'
