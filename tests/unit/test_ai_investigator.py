"""
tests/unit/test_ai_investigator.py
════════════════════════════════════
Unit tests for sin.agent.ai_investigator.

All Groq API calls and scanner tool calls are mocked.
No network I/O, no live devices.
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sin.agent.ai_investigator import (
    MAX_TOOLS,
    TOOL_MANIFEST,
    AIInvestigator,
    _parse_json,
    _TOOL_EXECUTORS,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

API_KEY = "test-groq-key"

DEVICE = {
    "ip_address":      "192.168.30.50",
    "open_ports":      [554, 80, 34567],
    "manufacturer":    "Hikvision",
    "model":           "DS-2CD2142FWD",
    "firmware":        "V5.4.0",
    "mac_address":     "bc:ad:28:aa:bb:cc",
    "device_type":     "camera",
    "vulnerabilities": [
        {"type": "Privacy Leak (RTSP)", "cve": "", "severity": "MEDIUM"},
    ],
}

VALID_PLAN_RESPONSE   = '["rtsp_probe_open", "cve_lookup"]'
INVALID_JSON_RESPONSE = "Sorry, I cannot help with that."
VALID_ADVISORY = json.dumps({
    "risk_verdict":        "HIGH",
    "attack_narrative":    "Attacker gains unauthenticated RTSP access then pivots via SDK.",
    "attack_chain":        ["Step 1: RTSP open", "Step 2: SDK creds"],
    "confirmed_findings":  [{"severity": "HIGH", "type": "RTSP", "cve": "", "description": "x", "source": "investigator"}],
    "recommended_actions": ["Change RTSP credentials", "Patch firmware"],
})


# ── _parse_json ───────────────────────────────────────────────────────────────

class TestParseJson:
    def test_valid_list(self):
        assert _parse_json('["a", "b"]', fallback=[]) == ["a", "b"]

    def test_valid_dict(self):
        assert _parse_json('{"k": 1}', fallback={}) == {"k": 1}

    def test_invalid_json_returns_fallback(self):
        assert _parse_json("not json", fallback=[]) == []

    def test_none_returns_fallback(self):
        assert _parse_json(None, fallback="default") == "default"


# ── Tool manifest completeness ────────────────────────────────────────────────

class TestToolManifest:
    def test_manifest_keys_match_executors(self):
        assert set(TOOL_MANIFEST.keys()) == set(_TOOL_EXECUTORS.keys())

    def test_all_tools_have_descriptions(self):
        for tool, desc in TOOL_MANIFEST.items():
            assert len(desc) > 10, f"Tool {tool} has empty description"


# ── AIInvestigator._plan ──────────────────────────────────────────────────────

class TestPlan:
    @pytest.mark.asyncio
    async def test_returns_valid_tool_list(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = VALID_PLAN_RESPONSE
            inv  = AIInvestigator(api_key=API_KEY)
            plan = await inv._plan(DEVICE)
        assert plan == ["rtsp_probe_open", "cve_lookup"]

    @pytest.mark.asyncio
    async def test_filters_hallucinated_tool_names(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = '["rtsp_probe_open", "made_up_tool", "cve_lookup"]'
            inv  = AIInvestigator(api_key=API_KEY)
            plan = await inv._plan(DEVICE)
        assert "made_up_tool" not in plan
        assert "rtsp_probe_open" in plan

    @pytest.mark.asyncio
    async def test_returns_empty_on_invalid_json(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = INVALID_JSON_RESPONSE
            inv  = AIInvestigator(api_key=API_KEY)
            plan = await inv._plan(DEVICE)
        assert plan == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_none_response(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = None
            inv  = AIInvestigator(api_key=API_KEY)
            plan = await inv._plan(DEVICE)
        assert plan == []

    @pytest.mark.asyncio
    async def test_respects_max_tools_limit(self):
        many_tools = json.dumps(list(_TOOL_EXECUTORS.keys()) * 3)
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = many_tools
            inv  = AIInvestigator(api_key=API_KEY)
            plan = await inv._plan(DEVICE)
        assert len(plan) <= MAX_TOOLS


# ── AIInvestigator._execute ───────────────────────────────────────────────────

class TestExecute:
    def setup_method(self):
        self.inv = AIInvestigator(api_key=API_KEY)

    def test_calls_correct_executor(self):
        mock_result = {"found": True, "finding": {"severity": "CRITICAL"}}
        with patch.dict(_TOOL_EXECUTORS, {"rtsp_probe_open": MagicMock(return_value=mock_result)}):
            evidence = self.inv._execute(DEVICE, ["rtsp_probe_open"])
        assert len(evidence) == 1
        assert evidence[0]["tool"] == "rtsp_probe_open"
        assert evidence[0]["status"] == "ok"
        assert evidence[0]["result"] == mock_result

    def test_skips_unknown_tool_name(self):
        evidence = self.inv._execute(DEVICE, ["nonexistent_tool"])
        assert evidence == []

    def test_handles_tool_exception_gracefully(self):
        with patch.dict(_TOOL_EXECUTORS, {"rtsp_probe_open": MagicMock(side_effect=RuntimeError("boom"))}):
            evidence = self.inv._execute(DEVICE, ["rtsp_probe_open"])
        assert evidence[0]["status"] == "error"
        assert evidence[0]["result"] == {}

    def test_evidence_contains_duration_ms(self):
        with patch.dict(_TOOL_EXECUTORS, {"snmp_query": MagicMock(return_value={"found": False})}):
            evidence = self.inv._execute(DEVICE, ["snmp_query"])
        assert "duration_ms" in evidence[0]
        assert isinstance(evidence[0]["duration_ms"], int)

    def test_multiple_tools_all_executed(self):
        with patch.dict(_TOOL_EXECUTORS, {
            "rtsp_probe_open":  MagicMock(return_value={"found": False}),
            "http_cred_check":  MagicMock(return_value={"found": False}),
        }):
            evidence = self.inv._execute(DEVICE, ["rtsp_probe_open", "http_cred_check"])
        assert len(evidence) == 2
        tools = [e["tool"] for e in evidence]
        assert "rtsp_probe_open" in tools
        assert "http_cred_check" in tools


# ── AIInvestigator._synthesize ────────────────────────────────────────────────

class TestSynthesize:
    @pytest.mark.asyncio
    async def test_returns_valid_advisory(self):
        evidence = [{"tool": "rtsp_probe_open", "status": "ok", "result": {"found": True}}]
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = VALID_ADVISORY
            inv     = AIInvestigator(api_key=API_KEY)
            advisory = await inv._synthesize(DEVICE, evidence)
        assert advisory["risk_verdict"] == "HIGH"
        assert "attack_narrative" in advisory
        assert isinstance(advisory["attack_chain"], list)

    @pytest.mark.asyncio
    async def test_returns_fallback_on_invalid_json(self):
        evidence = []
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = "not json at all"
            inv     = AIInvestigator(api_key=API_KEY)
            advisory = await inv._synthesize(DEVICE, evidence)
        assert advisory["risk_verdict"] == "UNKNOWN"
        assert advisory.get("synthesis_error") is True

    @pytest.mark.asyncio
    async def test_returns_fallback_on_none_response(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.return_value = None
            inv     = AIInvestigator(api_key=API_KEY)
            advisory = await inv._synthesize(DEVICE, [])
        assert advisory["risk_verdict"] == "UNKNOWN"


# ── AIInvestigator.investigate — full flow ────────────────────────────────────

class TestInvestigate:
    @pytest.mark.asyncio
    async def test_full_flow_returns_correct_structure(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq, \
             patch.dict(_TOOL_EXECUTORS, {
                 "rtsp_probe_open": MagicMock(return_value={"found": True, "finding": None}),
                 "cve_lookup":      MagicMock(return_value={"found": False, "cves": []}),
             }):
            mock_groq.side_effect = [VALID_PLAN_RESPONSE, VALID_ADVISORY]
            inv    = AIInvestigator(api_key=API_KEY)
            report = await inv.investigate(DEVICE)

        assert report["ip"]      == DEVICE["ip_address"]
        assert report["vendor"]  == DEVICE["manufacturer"]
        assert report["rounds"]  == 2
        assert report["model"]   == "llama-3.3-70b-versatile"
        assert isinstance(report["investigation_steps"], list)
        assert isinstance(report["advisory"], dict)

    @pytest.mark.asyncio
    async def test_advisory_has_required_keys(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq, \
             patch.dict(_TOOL_EXECUTORS, {
                 "rtsp_probe_open": MagicMock(return_value={"found": False}),
             }):
            mock_groq.side_effect = ['["rtsp_probe_open"]', VALID_ADVISORY]
            inv    = AIInvestigator(api_key=API_KEY)
            report = await inv.investigate(DEVICE)

        advisory = report["advisory"]
        for key in ("risk_verdict", "attack_narrative", "attack_chain",
                    "confirmed_findings", "recommended_actions"):
            assert key in advisory, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_evidence_has_required_keys(self):
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq, \
             patch.dict(_TOOL_EXECUTORS, {
                 "snmp_query": MagicMock(return_value={"found": True, "telemetry": {}}),
             }):
            mock_groq.side_effect = ['["snmp_query"]', VALID_ADVISORY]
            inv    = AIInvestigator(api_key=API_KEY)
            report = await inv.investigate(DEVICE)

        for step in report["investigation_steps"]:
            for key in ("tool", "status", "result", "duration_ms"):
                assert key in step, f"Evidence missing key: {key}"

    @pytest.mark.asyncio
    async def test_empty_plan_still_completes(self):
        """If AI returns empty plan, synthesis still runs with no evidence."""
        with patch("sin.agent.ai_investigator._groq", new_callable=AsyncMock) as mock_groq:
            mock_groq.side_effect = ["[]", VALID_ADVISORY]
            inv    = AIInvestigator(api_key=API_KEY)
            report = await inv.investigate(DEVICE)
        assert report["investigation_steps"] == []
        assert report["advisory"]["risk_verdict"] == "HIGH"
