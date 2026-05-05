"""
sin.agent.decision
══════════════════
Multi-factor threat scoring with hard false-positive guards and CISA KEV / EPSS Integration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from sin.utils.logger import get_logger

logger = get_logger("sin.agent.decision")

BASE_WEIGHTS: Dict[str, tuple] = {
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
    # Packet anomaly signals
    "pkt_arp_spoof":     (0.35, "ARP spoofing detected in traffic"),
    "pkt_port_scan":     (0.25, "Outbound port scan behaviour"),
    "pkt_dns_tunnel":    (0.30, "DNS tunnelling pattern"),
    "pkt_c2_beacon":     (0.40, "C2-like beacon traffic"),
    "pkt_lateral":       (0.30, "Lateral movement to internal hosts"),
    "pkt_data_exfil":    (0.35, "Large outbound transfer anomaly"),
    "pkt_brute_force":   (0.25, "Credential brute-force pattern"),
    "pkt_mirai_probe":   (0.45, "Mirai-family port probe pattern"),
}

CONFIDENCE_DAMPERS: Dict[str, float] = {
    "router":      1.0,
    "camera":      1.0,
    "nvr_dvr":     1.0,
    "iot":         0.95,
    "workstation": 0.70,
    "server":      0.60,
    "printer":     0.80,
    "unknown":     0.85,
}

# ACTIVATED: Require at least 2 distinct threat signals to allow a score > 0.65
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
    def evaluate(self, host: dict) -> ThreatVerdict:
        ip          = host.get("ip_address", "")
        device_type = host.get("device_type", "unknown")
        os_accuracy = host.get("os_accuracy", 0)
        vulns       = host.get("vulnerabilities", [])
        pkt_signals = host.get("_packet_signals", [])

        reasons: List[str] = []
        raw_score: float = 0.0
        signal_ids_seen: set = set()
        pkt_signal_count: int = 0
        
        # Track highest EPSS and KEV status
        has_kev_hit = False
        highest_epss = 0.0

        # ── 1. Score from vulnerabilities & Intel ────────────────────────────
        for vuln in vulns:
            # Check Intel
            if vuln.get("in_kev"):
                has_kev_hit = True
            
            epss = vuln.get("epss", 0.0)
            if epss > highest_epss:
                highest_epss = epss

            # Score based on sig_id or generic severity
            sig_id = vuln.get("sig_id", "")
            if not sig_id:
                sev = vuln.get("severity", "LOW").upper()
                if sev == "CRITICAL": raw_score += 0.80
                elif sev == "HIGH":   raw_score += 0.60
                
                vuln_type = vuln.get("type", "generic_vuln")
                if vuln_type not in signal_ids_seen:
                    signal_ids_seen.add(vuln_type)
                    reasons.append(f"[{sev}] {vuln.get('description', vuln_type)}")
                continue

            if sig_id in signal_ids_seen:
                continue
                
            weight, label = BASE_WEIGHTS.get(sig_id, (0.0, ""))
            if weight > 0.0:
                raw_score += weight
                signal_ids_seen.add(sig_id)
                reasons.append(f"[{vuln.get('severity','?')}] {label}")

        # ── 2. Apply Threat Intel Boosters (KEV & EPSS) ──────────────────────
        if has_kev_hit:
            raw_score += 0.40 # Massive boost for known exploited vulnerabilities
            reasons.append("[INTEL] CISA KEV Catalog Match (+0.40 boost)")
            # Automatically satisfy the FP guard because CISA verified it
            signal_ids_seen.add("KEV_OVERRIDE") 

        if highest_epss >= 0.10: # If probability is > 10%
            boost = min(0.30, highest_epss) # Boost up to 0.30
            raw_score += boost
            reasons.append(f"[INTEL] High EPSS Probability: {highest_epss:.1%} (+{boost:.2f} boost)")

        # ── 3. Score from packet anomaly signals ──────────────────────────────
        base_score_before_packets = raw_score
        for sig in pkt_signals:
            sig_type = sig.get("type", "")
            if not sig_type or sig_type in signal_ids_seen:
                continue
            weight, label = BASE_WEIGHTS.get(sig_type, (0.0, ""))
            if weight > 0.0 and (base_score_before_packets > 0 or weight >= 0.35):
                raw_score += weight
                signal_ids_seen.add(sig_type)
                reasons.append(f"[TRAFFIC] {label}")
                pkt_signal_count += 1

        raw_score = min(raw_score, 1.0)
        if raw_score < 0.01:
            return ThreatVerdict(ip=ip, device_type=device_type)

        # ── 4. Confidence Adjustment & Guards ─────────────────────────────────
        confidence = raw_score
        signal_count = len(signal_ids_seen)

        if signal_count < FP_GUARD_MIN_SIGNALS:
            confidence = min(confidence, 0.65)
            reasons.append(f"[GUARD] Only {signal_count} independent signal(s) — capped at 0.65")

        damper = CONFIDENCE_DAMPERS.get(device_type, 0.85)
        confidence *= damper
        if damper < 1.0:
            reasons.append(f"[DAMPER] Device type '{device_type}' (x{damper:.2f})")

        confidence = round(min(confidence, 1.0), 4)

        # ── 5. Severity band ──────────────────────────────────────────────────
        if confidence >= 0.80:
            severity, action = "CRITICAL", "isolate"
        elif confidence >= 0.60:
            severity, action = "HIGH", "quarantine"
        elif confidence >= 0.40:
            severity, action = "MEDIUM", "alert"
        elif confidence >= 0.10:
            severity, action = "LOW", "monitor"
        else:
            severity, action = "CLEAN", "none"

        return ThreatVerdict(
            score=round(raw_score, 4), confidence=confidence, severity=severity,
            reasons=reasons, recommended_action=action, signal_count=signal_count,
            packet_signals_count=pkt_signal_count, device_type=device_type, ip=ip,
        )
