package frostgate.defend

test_allow_default if {
  test_input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.login",
    "payload": {}
  }
  allow with input as test_input
  reasons_with := reasons with input as test_input
  count(reasons_with) == 0
}

test_deny_missing_tenant if {
  test_input := {
    "path": "/defend",
    "event_type": "auth.login",
    "payload": {}
  }
  not allow with input as test_input
  reasons_with := reasons with input as test_input
  reasons_with[_] == "missing_tenant"
}

test_deny_bruteforce_threshold if {
  test_input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.bruteforce",
    "payload": {"fail_count": 10}
  }
  not allow with input as test_input
  reasons_with := reasons with input as test_input
  reasons_with[_] == "bruteforce_threshold"
}
