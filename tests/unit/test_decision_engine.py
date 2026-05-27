import pytest
from sin.agent.decision import DecisionEngine

def test_decision_engine_clean_device():
    engine = DecisionEngine()
    host = {"ip_address": "192.168.1.5", "device_type": "workstation", "vulnerabilities": []}
    verdict = engine.evaluate(host)
    assert verdict.severity == "CLEAN"
    assert verdict.score == 0.0

def test_decision_engine_critical_threat():
    engine = DecisionEngine()
    # Mocking a device with Telnet (port 23) and a KEV-confirmed vulnerability
    host = {
        "ip_address": "192.168.1.10",
        "device_type": "camera",
        "open_ports": [23],
        "vulnerabilities": [{"cve": "CVE-2017-7921", "severity": "CRITICAL", "in_kev": True}]
    }
    verdict = engine.evaluate(host)
    assert verdict.severity == "CRITICAL"
    assert verdict.score > 0.5
