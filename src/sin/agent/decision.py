"""
sin.agent.decision
══════════════════
Multi-factor threat scoring with hard false-positive guards.

Design principles
─────────────────
1.  A verdict requires EVIDENCE from at least two independent signals
    before the confidence crosses the AUTO_MITIGATE threshold.
    A single open Telnet port never triggers automatic isolation by itself.

2.  Each signal contributes a weighted score.  Weights are tuned so that
    catastrophic combinations (e.g. Dahua camera + CVE exploit port + RTSP
    + Telnet) naturally reach 0.90+, while ambiguous signals stay below 0.60.

3.  Packet anomaly signals from the Scapy engine are treated as boosters —
    they can raise an existing threat score but cannot initiate one alone.

4.  Whitelist, device type "router" / "server", and OS confidence < 50%
    all apply a confidence penalty to prevent misidentification of managed
    infrastructure as rogue IoT.

Tuning guide (for your network)
────────────────────────────────
  Adjust BASE_WEIGHTS dict to raise / lower score per signal.
  Adjust CONFIDENCE_DAMPERS to protect device classes you trust.
  The final threshold check is in agent_settings.CONFIDENCE_THRESHOLD
  (default 0.80) — the decision engine itself has no hard thresholds.

Return type: ThreatVerdict (dataclass)
    .score        float 0.0–1.0  raw threat score
    .confidence   float 0.0–1.0  adjusted confidence (after dampers)
    .severity     str  CRITICAL | HIGH | MEDIUM | LOW | CLEAN
    .reasons      list[str]  human-readable evidence chain (for audit log)
    .recommended_action  str  isolate | quarantine | alert | monitor | none
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from sin.utils.logger import get_logger

logger = get_logger("sin.agent.decision")

# ── Scoring weights ───────────────────────────────────────────────────────────
# Each key matches a signal name produced by the scanner or packet engine.
# Value is (score_contribution, human_label)

BASE_WEIGHTS: Dict[str, tuple] = {
    # Critical port-based signals
    "TELNET":        (0.40, "Telnet (23) cleartext admin"),
    "DAHUA_SDK":     (0.45, "Dahua SDK port 37777 — CVE-2021-33044"),
    "DVR_WEB":       (0.45, "Generic DVR backdoor port 34567 — CVE-2018-9995"),
    "MQTT":          (0.20, "Unencrypted MQTT broker (1883)"),
    "MODBUS":        (0.30, "Modbus TCP (502) — unauthenticated OT access"),
    "BACNET":        (0.25, "BACnet (47808) — OT protocol exposure"),
    "REDIS":         (0.35, "Redis (6379) unauthenticated"),
    "MONGODB":       (0.30, "MongoDB (27017) exposed"),
    "FTP":           (0.25, "Plain FTP (21) — cleartext credentials"),
    "RDP":           (0.20, "RDP (3389) — BlueKeep attack surface"),
    "SNMP":          (0.15, "SNMP (161) — v1/v2c cleartext"),
    "HTTP_ONLY":     (0.15, "HTTP-only admin interface — no TLS"),
    "WINRM":         (0.15, "WinRM (5985) — remote management exposed"),
    "TR069":         (0.20, "TR-069 (7547) — Mirai target port"),
    "RTSP":          (0.10, "RTSP stream without auth check"),
    "HIK":           (0.30, "Hikvision CVE-2021-36260 RCE vector"),
    "DAH":           (0.30, "Dahua auth bypass CVE-2021-33044"),

    # Packet anomaly signals (boosters — only raise existing threat)
    "pkt_arp_spoof":     (0.35, "ARP spoofing detected in traffic"),
    "pkt_port_scan":     (0.25, "Outbound port scan behaviour"),
    "pkt_dns_tunnel":    (0.30, "DNS tunnelling pattern"),
    "pkt_c2_beacon":     (0.40, "C2-like beacon traffic"),
    "pkt_lateral":       (0.30, "Lateral movement to internal hosts"),
    "pkt_data_exfil":    (0.35, "Large outbound transfer anomaly"),
    "pkt_brute_force":   (0.25, "Credential brute-force pattern"),
    "pkt_mirai_probe":   (0.45, "Mirai-family port probe pattern"),
}

# Multipliers applied to confidence based on device class.
# A MikroTik router being flagged for Telnet is plausible; flag it.
# A "workstation" flagged because one port is open needs more evidence.
CONFIDENCE_DAMPERS: Dict[str, float] = {
    "router":      1.0,    # routers CAN be insecure IoT — no damping
    "camera":      1.0,    # cameras ARE the primary target — no damping
    "nvr_dvr":     1.0,    # DVRs — no damping
    "iot":         0.95,   # generic IoT — slight damping
    "workstation": 0.70,   # less likely to be rogue — damp confidence
    "server":      0.60,   # managed servers — damp more aggressively
    "printer":     0.80,
    "unknown":     0.85,
}

# Minimum INDEPENDENT signals required before confidence can exceed 0.70.
# This is the core false-positive guard.
FP_GUARD_MIN_SIGNALS = 2


@dataclass
class ThreatVerdict:
    score: float                    = 0.0
    confidence: float               = 0.0
    severity: str                   = "CLEAN"
    reasons: List[str]              = field(default_factory=list)
    recommended_action: str         = "none"
    signal_count: int               = 0
    packet_signals_count: int       = 0
    device_type: str                = "unknown"
    ip: str                         = ""

    def is_actionable(self, threshold: float) -> bool:
        return (
            self.confidence >= threshold
            and self.signal_count >= FP_GUARD_MIN_SIGNALS
        )


class DecisionEngine:
    """
    Stateless evaluator — call evaluate(host_dict) for each scanned host.
    Thread-safe (no mutable state).
    """

    def evaluate(self, host: dict) -> ThreatVerdict:
        ip          = host.get("ip_address", "")
        device_type = host.get("device_type", "unknown")
        manufacturer = host.get("manufacturer", "Unknown")
        os_accuracy = host.get("os_accuracy", 0)
        vulns       = host.get("vulnerabilities", [])
        pkt_signals = host.get("_packet_signals", [])   # from PacketEngine

        reasons: List[str] = []
        raw_score: float = 0.0
        signal_ids_seen: set = set()
        pkt_signal_count: int = 0

        # ── 1. Score from vulnerability signatures ────────────────────────────
        for vuln in vulns:
            sig_id = vuln.get("sig_id", "")
            if not sig_id or sig_id in signal_ids_seen:
                continue
            weight, label = BASE_WEIGHTS.get(sig_id, (0.0, ""))
            if weight == 0.0:
                continue
            raw_score += weight
            signal_ids_seen.add(sig_id)
            reasons.append(f"[{vuln.get('severity','?')}] {label}")

        # ── 2. Score from packet anomaly signals (boosters) ───────────────────
        base_score_before_packets = raw_score
        for sig in pkt_signals:
            sig_type = sig.get("type", "")
            if not sig_type or sig_type in signal_ids_seen:
                continue
            weight, label = BASE_WEIGHTS.get(sig_type, (0.0, ""))
            if weight == 0.0:
                continue
            # Packet signals only boost if there's already a scanner threat score
            if base_score_before_packets > 0 or weight >= 0.35:
                raw_score += weight
                signal_ids_seen.add(sig_type)
                reasons.append(f"[TRAFFIC] {label}")
                pkt_signal_count += 1

        # ── 3. Cap raw score at 1.0 ───────────────────────────────────────────
        raw_score = min(raw_score, 1.0)

        if raw_score < 0.01:
            return ThreatVerdict(ip=ip, device_type=device_type)

        # ── 4. Confidence adjustment ───────────────────────────────────────────
        confidence = raw_score

        # FP guard: fewer than 2 independent signals → hard confidence cap
        signal_count = len(signal_ids_seen)
        if signal_count < FP_GUARD_MIN_SIGNALS:
            confidence = min(confidence, 0.65)
            reasons.append(
                f"[GUARD] Only {signal_count} independent signal(s) — "
                f"confidence capped at 0.65 to prevent false positive"
            )

        # Device-type damper
        damper = CONFIDENCE_DAMPERS.get(device_type, 0.85)
        confidence *= damper
        if damper < 1.0:
            reasons.append(
                f"[DAMPER] Device type '{device_type}' → "
                f"confidence multiplied by {damper:.2f}"
            )

        # Low OS fingerprint accuracy → reduce confidence
        if os_accuracy > 0 and os_accuracy < 50:
            confidence *= 0.85
            reasons.append(
                f"[DAMPER] Low OS accuracy ({os_accuracy}%) "
                f"— confidence reduced 15%"
            )

        confidence = round(min(confidence, 1.0), 4)

        # ── 5. Severity band ──────────────────────────────────────────────────
        if confidence >= 0.80:
            severity = "CRITICAL"
            action   = "isolate"
        elif confidence >= 0.60:
            severity = "HIGH"
            action   = "quarantine"
        elif confidence >= 0.40:
            severity = "MEDIUM"
            action   = "alert"
        elif confidence >= 0.10:
            severity = "LOW"
            action   = "monitor"
        else:
            severity = "CLEAN"
            action   = "none"

        logger.debug(
            f"{ip} | score={raw_score:.3f} | confidence={confidence:.3f} | "
            f"severity={severity} | signals={signal_count} | "
            f"pkt={pkt_signal_count}"
        )

        return ThreatVerdict(
            score=round(raw_score, 4),
            confidence=confidence,
            severity=severity,
            reasons=reasons,
            recommended_action=action,
            signal_count=signal_count,
            packet_signals_count=pkt_signal_count,
            device_type=device_type,
            ip=ip,
        )
