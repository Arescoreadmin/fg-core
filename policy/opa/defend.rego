package frostgate.defend

default allow = false
default reasons = []

deny_reason contains "missing_tenant" if {
  input.path == "/defend"
  not input.tenant_id
}

deny_reason contains "bruteforce_threshold" if {
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow if {
  count(deny_reason) == 0
}

reasons := [r | deny_reason[r]]
