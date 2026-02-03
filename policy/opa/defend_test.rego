package frostgate.defend

test_allow_default {
  input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.login",
    "payload": {}
  }
  allow with input as input
  reasons_with := reasons with input as input
  count(reasons_with) == 0
}

test_deny_missing_tenant {
  input := {
    "path": "/defend",
    "event_type": "auth.login",
    "payload": {}
  }
  not allow with input as input
  reasons_with := reasons with input as input
  reasons_with[_] == "missing_tenant"
}

test_deny_bruteforce_threshold {
  input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.bruteforce",
    "payload": {"fail_count": 10}
  }
  not allow with input as input
  reasons_with := reasons with input as input
  reasons_with[_] == "bruteforce_threshold"
}
