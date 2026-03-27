#!/usr/bin/env bash
set -euo pipefail

changed="$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"

if [ "${changed:-0}" -gt 5 ]; then
  jq -n --arg msg "Scope warning: more than 5 files changed. Re-check whether the diff is too broad." '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: $msg
    }
  }'
else
  jq -n '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: "Keep the diff narrow and run the smallest valid verification."
    }
  }'
fi
