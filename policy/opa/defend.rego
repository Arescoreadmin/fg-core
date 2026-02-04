package frostgate.defend

default allow = false
default reasons = []

reasons_set["missing_tenant"] {
  input.path == "/defend"
  not input.tenant_id
}

reasons_set["bruteforce_threshold"] {
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow {
  count(reasons_set) == 0
}

reasons := [r | r := keys(reasons_set)[_]]
