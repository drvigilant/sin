"""
sin.agent.ai_investigator
══════════════════════════
Multi-step agentic security investigator.

Reasoning loop (3 rounds, 2 Groq calls):
  Round 1 — PLAN:      Groq selects which scanner tools to run
  Round 2 — EXECUTE:   Python runs selected tools against the live device
  Round 3 — SYNTHESIZE: Groq reasons over all evidence → attack narrative

The key output is the attack_narrative and attack_chain — an explanation of
HOW an attacker would chain confirmed findings into a full compromise.
This is the differentiator vs single-shot /ai/audit.

Groq calls: 2 (plan + synthesize)
Max tools:  5
Per-tool timeout: 8 seconds (runs in thread, non-blocking)
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Any, Dict, List, Optional

import httpx

from sin.utils.logger import get_logger

logger = get_logger("sin.agent.ai_investigator")

# ── Constants ─────────────────────────────────────────────────────────────────
GROQ_URL         = "https://api.groq.com/openai/v1/chat/completions"
PLAN_MODEL       = "llama-3.3-70b-versatile"
SYNTH_MODEL      = "llama-3.3-70b-versatile"
TEMPERATURE      = 0.1
PLAN_MAX_TOKENS  = 300
SYNTH_MAX_TOKENS = 1500
TOOL_TIMEOUT_S   = 8
MAX_TOOLS        = 5

# ── Tool manifest — shown to Groq during planning ─────────────────────────────
TOOL_MANIFEST: Dict[str, str] = {
    "rtsp_probe_open": (
        "Test if the RTSP stream is accessible without credentials. "
        "Use when port 554, 8554, or 10554 is open."
    ),
    "rtsp_probe_creds": (
        "Test default RTSP credentials (admin/admin, admin/12345, etc.). "
        "Use when RTSP port is open and stream is auth-protected."
    ),
    "http_cred_check": (
        "Test default HTTP and Xiongmai SDK credentials. "
        "Use when ports 80, 8080, 8000, or 34567 are open."
    ),
    "snmp_query": (
        "Retrieve SNMP telemetry: uptime, CPU load, sysDescr, hostname. "
        "Use when device type or firmware version is unknown."
    ),
    "cve_lookup": (
        "Query NVD for CVEs matching this vendor, model, and firmware. "
        "Use when vendor or firmware version is known."
    ),
}

_TOOL_MANIFEST_TEXT = "\n".join(
    f'  "{k}": {v}' for k, v in TOOL_MANIFEST.items()
)


# ── Groq API helper ───────────────────────────────────────────────────────────

async def _groq(
    api_key: str,
    model: str,
    prompt: str,
    max_tokens: int,
) -> Optional[str]:
    """
    Single Groq API call. Returns raw text content, or None on any failure.
    Strips markdown fences automatically.
    """
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": TEMPERATURE,
                    "max_tokens": max_tokens,
                },
            )
        if resp.status_code != 200:
            logger.error("Groq %s error: %d %s", model, resp.status_code, resp.text[:200])
            return None
        raw = resp.json()["choices"][0]["message"]["content"].strip()
        fence = "`" * 3
        if raw.startswith(fence):
            parts = raw.split(fence)
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
        return raw.strip()
    except Exception as exc:
        logger.error("Groq call failed: %s", exc)
        return None


def _parse_json(text: Optional[str], fallback: Any) -> Any:
    if not text:
        return fallback
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        logger.warning("JSON parse failed on: %s...", (text or "")[:120])
        return fallback


# ── Tool executors (pure Python — no Groq) ────────────────────────────────────

def _exec_rtsp_probe_open(device: Dict) -> Dict:
    from sin.scanner.rtsp_probe import rtsp_probe
    ip    = device["ip_address"]
    ports = set(device.get("open_ports", []))
    port  = next((p for p in [554, 8554, 10554] if p in ports), 554)
    result = rtsp_probe.probe(ip, port, vendor=device.get("manufacturer", ""))
    return {"found": result is not None, "finding": result}


def _exec_rtsp_probe_creds(device: Dict) -> Dict:
    from sin.scanner.rtsp_probe import rtsp_probe
    ip    = device["ip_address"]
    ports = set(device.get("open_ports", []))
    port  = next((p for p in [554, 8554, 10554] if p in ports), 554)
    result = rtsp_probe.probe_with_creds(ip, port, vendor=device.get("manufacturer", ""))
    return {"found": result is not None, "finding": result}


def _exec_http_cred_check(device: Dict) -> Dict:
    from sin.scanner.cred_check import cred_checker
    result = cred_checker.check(device)
    return {"found": result is not None, "finding": result}


def _exec_snmp_query(device: Dict) -> Dict:
    from sin.scanner.snmp_telemetry import SNMPTelemetryProber
    result = SNMPTelemetryProber().probe(
        device["ip_address"], device.get("open_ports", [])
    )
    return {"found": bool(result), "telemetry": result or {}}


def _exec_cve_lookup(device: Dict) -> Dict:
    from sin.scanner.cpe_correlator import CPECorrelator
    cves = CPECorrelator().correlate(device)
    return {"found": bool(cves), "cves": cves[:10]}


# Registry — keys must match TOOL_MANIFEST exactly
_TOOL_EXECUTORS: Dict[str, Any] = {
    "rtsp_probe_open":  _exec_rtsp_probe_open,
    "rtsp_probe_creds": _exec_rtsp_probe_creds,
    "http_cred_check":  _exec_http_cred_check,
    "snmp_query":       _exec_snmp_query,
    "cve_lookup":       _exec_cve_lookup,
}


# ── AIInvestigator ────────────────────────────────────────────────────────────

class AIInvestigator:
    """
    Agentic security investigator — multi-step reasoning over live device data.

    Usage (from async context):
        inv = AIInvestigator(api_key=os.getenv("GROQ_API_KEY"))
        report = await inv.investigate(device_data)
    """

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def investigate(self, device: Dict) -> Dict:
        """
        Full investigation pipeline. Returns structured report dict.
        """
        ip = device.get("ip_address", "unknown")
        logger.info("[investigator] Starting for %s", ip)

        # Round 1: Plan — AI selects tools
        tool_plan = await self._plan(device)
        logger.info("[investigator] %s plan=%s", ip, tool_plan)

        # Round 2: Execute — Python runs the tools (non-blocking via thread)
        loop = asyncio.get_running_loop()
        evidence = await loop.run_in_executor(
            None, self._execute, device, tool_plan
        )
        logger.info("[investigator] %s evidence from %d tools", ip, len(evidence))

        # Round 3: Synthesize — AI reasons over all evidence
        advisory = await self._synthesize(device, evidence)
        logger.info("[investigator] %s synthesis complete", ip)

        return {
            "ip":                  ip,
            "vendor":              device.get("manufacturer") or device.get("vendor") or "Unknown",
            "investigation_steps": evidence,
            "advisory":            advisory,
            "model":               SYNTH_MODEL,
            "rounds":              2,
        }

    # ── Round 1 ───────────────────────────────────────────────────────────────

    async def _plan(self, device: Dict) -> List[str]:
        """Ask Groq which tools to run. Returns list of valid tool names."""
        ports          = device.get("open_ports", [])
        existing_types = [f.get("type", "") for f in device.get("vulnerabilities", [])]
        existing_str   = ", ".join(existing_types) if existing_types else "none"
        manufacturer   = device.get("manufacturer") or device.get("vendor") or "unknown"

        prompt = f"""You are a security investigation planner for IoT/OT devices.
Select up to {MAX_TOOLS} tools to investigate this device further.

AVAILABLE TOOLS:
{_TOOL_MANIFEST_TEXT}

DEVICE STATE:
- IP: {device.get("ip_address", "unknown")}
- Vendor: {manufacturer}
- Model: {device.get("model") or "unknown"}
- Firmware: {device.get("firmware") or "unknown"}
- Open ports: {ports}
- Already confirmed: {existing_str}

SELECTION RULES — violating these produces a rejected plan:
- Only select rtsp_probe_open or rtsp_probe_creds if 554, 8554, or 10554 is in open ports.
- Only select http_cred_check if 80, 8080, 8000, or 34567 is in open ports.
- Only select cve_lookup if vendor is not "unknown".
- Do NOT select tools for findings already confirmed above.
- Only select tools that would reveal NEW information.

Return ONLY a JSON array of tool name strings. No markdown, no explanation.
Example: ["rtsp_probe_open", "cve_lookup"]"""

        raw    = await _groq(self.api_key, PLAN_MODEL, prompt, PLAN_MAX_TOKENS)
        parsed = _parse_json(raw, fallback=[])
        if not isinstance(parsed, list):
            return []
        # Hard filter — never execute a tool not in our registry
        return [t for t in parsed if t in _TOOL_EXECUTORS][:MAX_TOOLS]

    # ── Round 2 ───────────────────────────────────────────────────────────────

    def _execute(self, device: Dict, tool_plan: List[str]) -> List[Dict]:
        """Run selected tools with per-tool timeout. Returns evidence list."""
        evidence: List[Dict] = []
        with ThreadPoolExecutor(max_workers=min(len(tool_plan) or 1, MAX_TOOLS)) as pool:
            for tool_name in tool_plan:
                executor = _TOOL_EXECUTORS.get(tool_name)
                if not executor:
                    logger.warning("[investigator] unknown tool skipped: %s", tool_name)
                    continue
                t0 = time.monotonic()
                try:
                    future = pool.submit(executor, device)
                    result = future.result(timeout=TOOL_TIMEOUT_S)
                    status = "ok"
                except FuturesTimeout:
                    result = {}
                    status = "timeout"
                    logger.warning("[investigator] tool %s timed out", tool_name)
                except Exception as exc:
                    result = {}
                    status = "error"
                    logger.warning("[investigator] tool %s error: %s", tool_name, exc)
                evidence.append({
                    "tool":        tool_name,
                    "status":      status,
                    "result":      result,
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                })
        return evidence

    # ── Round 3 ───────────────────────────────────────────────────────────────

    async def _synthesize(self, device: Dict, evidence: List[Dict]) -> Dict:
        """
        Reason over all gathered evidence. Returns structured advisory.
        Falls back to a minimal dict if Groq fails or returns malformed JSON.
        """
        existing_vulns   = device.get("vulnerabilities", [])
        existing_summary = json.dumps(
            [{"type": v.get("type"), "cve": v.get("cve"), "severity": v.get("severity")}
             for v in existing_vulns],
            indent=2,
        )
        evidence_summary = json.dumps(
            [{"tool": e["tool"], "status": e["status"], "result": e["result"]}
             for e in evidence],
            indent=2,
        )
        manufacturer = device.get("manufacturer") or device.get("vendor") or "unknown"

        prompt = f"""You are an expert IoT/OT security analyst. Analyse all evidence below.

DEVICE:
- IP: {device.get("ip_address", "unknown")}
- Vendor: {manufacturer}
- Model: {device.get("model") or "unknown"}
- Firmware: {device.get("firmware") or "unknown"}
- Open ports: {device.get("open_ports", [])}

CONFIRMED SCANNER FINDINGS:
{existing_summary}

INVESTIGATION EVIDENCE (gathered this session):
{evidence_summary}

Produce a security advisory. Return ONLY valid JSON — no markdown, no preamble:
{{
  "risk_verdict": "CRITICAL|HIGH|MEDIUM|LOW",
  "attack_narrative": "2-3 sentences: how an attacker chains these findings into a full compromise",
  "attack_chain": [
    "Step 1: Initial access via ...",
    "Step 2: Lateral movement / persistence via ...",
    "Step 3: Impact: ..."
  ],
  "confirmed_findings": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "type": "finding category",
      "cve": "CVE-XXXX-XXXXX or empty string",
      "description": "specific technical detail grounded in the evidence",
      "source": "scanner|investigator"
    }}
  ],
  "recommended_actions": [
    "Concrete remediation step 1",
    "Concrete remediation step 2"
  ]
}}"""

        raw    = await _groq(self.api_key, SYNTH_MODEL, prompt, SYNTH_MAX_TOKENS)
        parsed = _parse_json(raw, fallback=None)

        if isinstance(parsed, dict) and "risk_verdict" in parsed:
            return parsed

        # Graceful degradation — never crash the endpoint
        logger.warning("[investigator] synthesis returned unusable response")
        return {
            "risk_verdict":        "UNKNOWN",
            "attack_narrative":    "AI synthesis unavailable — review scanner findings manually.",
            "attack_chain":        [],
            "confirmed_findings":  [],
            "recommended_actions": ["Review the scanner findings and apply vendor patches."],
            "synthesis_error":     True,
        }
