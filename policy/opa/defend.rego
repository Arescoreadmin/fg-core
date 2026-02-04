package frostgate.defend

default allow = false
default reasons = {}

reasons["missing_tenant"] {
  input.path == "/defend"
  not input.tenant_id
}

reasons["bruteforce_threshold"] {
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow {
  count(reasons) == 0
}
