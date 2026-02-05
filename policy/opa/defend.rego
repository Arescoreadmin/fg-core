package frostgate.defend

import rego.v1
default allow := false

# reasons is a SET of strings (Rego v1)
reasons contains "missing_tenant" if {
  input.path == "/defend"
  not input.tenant_id
}

reasons contains "bruteforce_threshold" if {
  input.path == "/defend"
  input.event_type == "auth.bruteforce"
  input.payload.fail_count >= 10
}

allow if {
  count(reasons) == 0
}
