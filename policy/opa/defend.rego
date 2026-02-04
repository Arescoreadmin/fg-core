package frostgate.defend

default allow = false

reasons[reason] {
  reason := "missing_tenant"
  input.path == "/defend"
  not input.tenant_id
}

reasons[reason] {
  reason := "bruteforce_threshold"
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow {
  count(reasons) == 0
}
