def test_api_defend_exports_evaluate_shim():
    from api.defend import evaluate

    class Dummy:
        tenant_id = "t1"
        source = "s1"
        event_type = "auth"
        payload = {"failed_auths": 7, "src_ip": "1.2.3.4"}

    out = evaluate(Dummy())
    assert isinstance(out, tuple)
    assert len(out) == 5
    threat, rules, mitigations, anomaly, score = out
    assert threat in {"none", "low", "medium", "high", "critical"}
    assert isinstance(rules, list)
    assert isinstance(mitigations, list)
    assert isinstance(anomaly, float)
    assert isinstance(score, int)
