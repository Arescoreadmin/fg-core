package frostgate.defend

import rego.v1
test_allow_default if {
  inp := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.login",
    "payload": {}
  }

  allow with input as inp

  rs := reasons with input as inp
  count(rs) == 0
  not ("missing_tenant" in rs)
  not ("bruteforce_threshold" in rs)
}

test_deny_missing_tenant if {
  inp := {
    "path": "/defend",
    "event_type": "auth.login",
    "payload": {}
  }

  not allow with input as inp

  rs := reasons with input as inp
  "missing_tenant" in rs
}

test_deny_bruteforce_threshold if {
  inp := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.bruteforce",
    "payload": {"fail_count": 10}
  }

  not allow with input as inp

  rs := reasons with input as inp
  "bruteforce_threshold" in rs
}
