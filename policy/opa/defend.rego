package frostgate.defend

default allow = false
default reasons = []

deny_reason["missing_tenant"] {
  input.path == "/defend"
  not input.tenant_id
}

deny_reason["bruteforce_threshold"] {
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow {
  not deny_reason[_]
}

reasons := [r | deny_reason[r]]
