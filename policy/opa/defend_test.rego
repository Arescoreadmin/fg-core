package frostgate.defend

test_allow_default {
  test_input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.login",
    "payload": {}
  }
  allow with input as test_input
  reasons_with := reasons with input as test_input
  not reasons_with[_]
}

test_deny_missing_tenant {
  test_input := {
    "path": "/defend",
    "event_type": "auth.login",
    "payload": {}
  }
  not allow with input as test_input
  reasons_with := reasons with input as test_input
  reasons_with["missing_tenant"]
}

test_deny_bruteforce_threshold {
  test_input := {
    "path": "/defend",
    "tenant_id": "t1",
    "event_type": "auth.bruteforce",
    "payload": {"fail_count": 10}
  }
  not allow with input as test_input
  reasons_with := reasons with input as test_input
  reasons_with["bruteforce_threshold"]
}
