import os
from typing import Dict, List, Tuple
from sin.utils.logger import get_logger
from sin.scanner.kev_intel import kev as _kev
from sin.scanner.epss_intel import epss as _epss
from sin.scanner.cred_check import cred_checker as _creds

logger = get_logger("sin.scanner.audit")

# ── Remediation playbooks ──────────────────────────────────────────────────────
# Keyed by CVE ID (uppercase) or finding type string.
# CVE keys take precedence over type keys.
REMEDIATION_DB: Dict[str, List[str]] = {
    # ── CVE-specific playbooks ─────────────────────────────────────────────────
    "CVE-2018-10088": [
        "Immediately block TCP port 34567 at the perimeter firewall (iptables: `iptables -I INPUT -p tcp --dport 34567 -j DROP`).",
        "Update Xiongmai firmware to version 4.02.R11.Xiongmai-8 or later via the web UI at http://<device-ip>/System/firmwareUpgrade.",
        "If firmware update is unavailable, replace the device — Xiongmai devices below firmware 2018-Q2 have no patch.",
        "Change the default admin password from '888888' via Setup → Account → Change Password.",
        "Disable the XMEye P2P cloud relay in Network → P2P → Disable to prevent botnet re-infection.",
    ],
    "CVE-2017-7921": [
        "Update Hikvision firmware to v5.4.5 build 170123 or later: Device Web UI → Configuration → System → Maintenance → Upgrade.",
        "Block unauthenticated access to the ISAPI endpoint: deny HTTP GET /ISAPI/* from untrusted networks at the firewall.",
        "Disable the 'Illegal Login' lockout bypass by enabling account lockout: Configuration → System → Security → Security Service → Enable Illegal Login Lock.",
        "Rotate all admin credentials immediately (default admin/12345 is widely known).",
        "Enable HTTPS-only access: Configuration → Network → Advanced Settings → HTTPS → Enable.",
    ],
    "CVE-2021-36260": [
        "Update Hikvision firmware to v5.5.800 or later (released 2021-09-18): Configuration → System → Maintenance → Upgrade.",
        "Block network access to port 80/443 from untrusted segments — this CVE is exploitable via the web management interface.",
        "Apply Hikvision Security Hardening Guide: disable SSH (port 22), Telnet (port 23), and UPnP.",
        "Monitor for POST requests to /SDK/webLanguage — the specific exploit endpoint for this RCE.",
    ],
    "CVE-2021-33044": [
        "Update Dahua firmware to the version published 2021-10-22 or later via Smart PSS or DMSS: Main Menu → Upgrade.",
        "Block TCP port 37777 (Dahua private protocol) at the perimeter — this CVE requires network access to that port.",
        "Disable the Dahua P2P cloud service: Main Menu → Network → TCP/IP → P2P → Disable.",
        "Change default credentials (admin/admin) via Main Menu → Account → Change Password.",
        "Enable two-factor authentication if on firmware ≥ 2.820: Main Menu → Account → 2FA Settings.",
    ],
    "CVE-2021-33045": [
        "Apply the same Dahua firmware patch as CVE-2021-33044 — both are fixed in the 2021-10-22 release.",
        "Block TCP port 37777 at the firewall.",
        "Audit all active sessions via Main Menu → System Info → Online User and terminate unknown sessions.",
    ],
    "CVE-2022-30525": [
        "Update Zyxel USG FLEX / ATP / VPN firmware to v5.30 or later via Web GUI → Maintenance → Firmware Upgrade.",
        "Block access to the web management interface (port 443/80) from the internet — apply an ACL on the WAN interface.",
        "Disable the CGI management endpoint if firmware update is not immediately possible: contact Zyxel TAC.",
        "Rotate all admin credentials and audit firewall rules for lateral movement.",
    ],
    "CVE-2023-20198": [
        "Apply Cisco IOS XE patch: upgrade to 17.9.4a, 17.6.6a, or 16.12.10a depending on your train.",
        "Immediately disable HTTP/HTTPS server if not required: `no ip http server` and `no ip http secure-server`.",
        "Check for implanted web shells via `show platform software fed active punt cpuq rates` and inspect /usr/binos/conf/nginx-conf/nginx.conf.",
        "Rotate all enable secrets and local usernames immediately.",
    ],
    # ── Finding-type playbooks (fallback when CVE is absent) ──────────────────
    "Cleartext Management": [
        "Disable Telnet immediately: `service telnet disable` or equivalent for your device OS.",
        "Enable SSH v2 as the replacement: set minimum SSH version to 2 and use 2048-bit RSA host keys.",
        "Block TCP port 23 at the perimeter firewall: `iptables -I INPUT -p tcp --dport 23 -j DROP`.",
        "Audit all devices for shared/default Telnet passwords — Mirai uses 62 known default credential pairs.",
        "If the device cannot disable Telnet, isolate it on a management VLAN with no internet routing.",
    ],
    "Insecure IoT Messaging": [
        "Enable MQTT broker authentication: set `allow_anonymous false` in mosquitto.conf and create user ACLs.",
        "Enable TLS on the MQTT broker (port 8883) and disable the plaintext listener on port 1883.",
        "Apply topic-level ACLs to restrict which clients can publish to control topics.",
        "If using cloud MQTT (AWS IoT, Azure IoT Hub), rotate all device certificates and revoke compromised ones.",
        "Block external access to port 1883 at the firewall; restrict to internal management VLAN only.",
    ],
    "Privacy Leak (RTSP)": [
        "Enable RTSP authentication: set username/password in the camera web UI under Configuration → Network → Video → RTSP Authentication.",
        "Use RTSP over TLS (RTSPS, port 322) or tunnel via HTTPS where the device supports it.",
        "Block TCP ports 554 and 8554 from untrusted networks at the firewall.",
        "Rotate the RTSP stream credentials — default rtsp://admin:12345@<ip>/stream is well-known.",
        "Enable digest authentication (stronger than basic) if supported: Configuration → Security → Authentication Method → Digest.",
    ],
    "Service Discovery Leak": [
        "Disable UPnP on the device: router/device web UI → Advanced → UPnP → Disable.",
        "Block UDP port 1900 (SSDP) at the perimeter to prevent external enumeration.",
        "Audit UPnP port mappings via `upnpc -l` and remove any unexpected external-to-internal forwarding rules.",
    ],
    "Industrial Control Exposure": [
        "Immediately isolate the device on a dedicated OT VLAN with no direct internet routing.",
        "Block TCP port 502 (Modbus) and UDP port 47808 (BACnet) at all IT/OT boundary firewalls.",
        "Apply the NIST ICS Security Guide (SP 800-82r2): enforce unidirectional data diodes between IT and OT segments.",
        "Audit all Modbus register reads/writes via an IDS (e.g., Claroty, Dragos) for unauthorized commands.",
        "If device cannot be patched, deploy a Modbus-aware application firewall (e.g., Tofino Xenon) in front of it.",
    ],
    "Backdoor Access": [
        "Update device firmware to the latest version to close known backdoor endpoints.",
        "Block all management ports (80, 443, 8000, 8080) from untrusted network segments.",
        "Change all credentials immediately — factory defaults are hardcoded in exploit toolkits.",
        "Enable audit logging and forward logs to a SIEM for anomalous configuration-change detection.",
    ],
    "Remote Code Execution": [
        "Patch or replace the device immediately — RCE with no authentication has zero acceptable residual risk.",
        "Block the exploited service port at the firewall while the patch is applied.",
        "Check for indicators of compromise: unexpected processes, outbound connections on non-standard ports.",
        "Restore from a known-good backup if compromise is suspected.",
    ],
    "Credential Leak": [
        "Change all device passwords immediately using strong, unique credentials (≥16 chars, mixed case + symbols).",
        "Enable account lockout after 5 failed attempts where supported.",
        "Audit active sessions and terminate any unknown logins.",
        "Segment the device to restrict credential replay attacks to a limited blast radius.",
    ],
    "Information Leak": [
        "Disable unauthenticated ONVIF discovery if not required: device web UI → Network → ONVIF → Disable or require authentication.",
        "Block UDP port 3702 (WS-Discovery) and multicast group 239.255.255.250 at the VLAN boundary.",
        "Disable SSDP if not required: block UDP port 1900 at the local switch.",
    ],
    "DEFAULT_CREDS_FOUND": [
        "Change default credentials immediately: access the device web UI and navigate to System → Account → Administrator.",
        "Set a password meeting complexity requirements: ≥12 chars, mixed case, numbers, symbols.",
        "Disable or rename the default 'admin' account where the device firmware supports it.",
        "Enable login attempt rate-limiting or account lockout (typically under Security → Authentication).",
        "Rotate credentials on all devices of the same model — default credentials are per-model, not per-device.",
    ],
}


def _attach_remediation(finding: Dict) -> Dict:
    """Add a remediation list to a single finding dict. Mutates in-place and returns it."""
    cve = (finding.get("cve") or "").upper()
    ftype = finding.get("type", "")
    steps = (
        REMEDIATION_DB.get(cve)
        or REMEDIATION_DB.get(ftype)
        or ["No specific remediation playbook available. Follow vendor security advisories and apply the principle of least privilege."]
    )
    finding.setdefault("remediation", steps)
    return finding

class AuditEngine:
    def __init__(self):
        # AI toggle for future DeepSeek/Ollama integration
        self.ai_enabled = False

    def evaluate_asset(self, device_data: Dict) -> Tuple[List[Dict], int, str]:
        """
        Interrogates device telemetry using multi-vendor heuristics.
        Returns: (vulnerabilities, risk_score, action)
        """
        vulnerabilities = []
        risk_score = 0
        
        ip = device_data.get("ip_address", "Unknown")
        mfr = (device_data.get("manufacturer") or "").lower()
        model = (device_data.get("model") or "Unknown")
        ports = set(device_data.get("open_ports", []))
        banners = str(device_data.get("banners", {})).lower()
        discovery = device_data.get("discovery_method", "TCP Scan")

        logger.info(f"🔎 Brain conducting deep heuristic audit for {ip} [{mfr}]...")

        # --- 🛡️ LAYER 1: DISCOVERY SOURCE TRUST ---
        if discovery == "Multimodal (ONVIF/SSDP)":
            vulnerabilities.append({
                "severity": "LOW",
                "type": "Information Leak",
                "description": f"Device exposed rich metadata via unauthenticated {discovery} probe."
            })
            risk_score += 10

        # --- 🛡️ LAYER 2: VENDOR-SPECIFIC CVE HEURISTICS ---
        
        # 1. Xiongmai (XM) / H.264 DVRs
        if "xiongmai" in mfr or "h264dvr" in banners:
            if 34567 in ports:
                vulnerabilities.append({
                    "severity": "CRITICAL",
                    "type": "Remote Code Execution",
                    "cve": "CVE-2018-10088",
                    "description": "Xiongmai DVR service on 34567 is unauthenticated. Massive risk of botnet hijacking."
                })
                risk_score += 90

        # 2. Hikvision
        if "hikvision" in mfr or 8000 in ports:
            if "hikvision-httppreview" in banners or 80 in ports:
                vulnerabilities.append({
                    "severity": "CRITICAL",
                    "type": "Backdoor Access",
                    "cve": "CVE-2017-7921",
                    "description": "Potential Hikvision backdoor. Allows unauthenticated configuration and snapshot export."
                })
                risk_score += 85

        # 3. Dahua
        if "dahua" in mfr or 37777 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Credential Leak",
                "cve": "CVE-2021-33044",
                "description": "Dahua authentication bypass vulnerability in the underlying RPC service."
            })
            risk_score += 75

        # --- 🛡️ LAYER 3: INSECURE PROTOCOL ANALYSIS ---

        # Telnet: The ultimate red flag
        if 23 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Cleartext Management",
                "description": "Telnet exposed. Credentials sent in plain text. Target for Mirai/Mozi botnets."
            })
            risk_score += 95

        # MQTT: IoT "Glue" often left open
        if 1883 in ports:
            vulnerabilities.append({
                "severity": "MEDIUM",
                "type": "Insecure IoT Messaging",
                "description": "MQTT broker detected. If unauthenticated, allows full control of IoT logic/data flow."
            })
            risk_score += 40

        # RTSP: Surveillance Privacy Risk
        if 554 in ports or 8554 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Privacy Leak (RTSP)",
                "description": "Unencrypted video stream detected. Risk of unauthenticated voyeurism."
            })
            risk_score += 50

        # UPnP/SSDP: Lateral Movement Aid
        if 1900 in ports:
            vulnerabilities.append({
                "severity": "LOW",
                "type": "Service Discovery Leak",
                "description": "UPnP/SSDP exposed. Aids attackers in mapping internal network topology."
            })
            risk_score += 15

        # Industrial / OT Protocols (Modbus/BACnet)
        if 502 in ports or 47808 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Industrial Control Exposure",
                "description": "OT/ICS protocol detected on standard network. Potential for physical infrastructure damage."
            })
            risk_score += 100

        # --- 🛡️ LAYER 4: DECISION LOGIC ---
        risk_score = min(risk_score, 100)

        if risk_score >= 80:
            action = "quarantine"
        elif risk_score >= 50:
            action = "alert_soc"
        elif risk_score >= 20:
            action = "monitor"
        else:
            action = "log_only"

        # ── LAYER 5: CISA KEV cross-reference ──────────────────────────────
        # Upgrade severity to CRITICAL for any CVE in the KEV catalog
        vulnerabilities = _kev.flag_kev_matches(vulnerabilities)
        kev_hits = [v for v in vulnerabilities if v.get("in_kev")]
        if kev_hits:
            risk_score = min(risk_score + 15, 100)
            action = "quarantine"

        # ── LAYER 7: EPSS scoring ───────────────────────────────────────────
        # Enrich every finding with EPSS probability and boosted priority_score
        vulnerabilities = _epss.enrich_findings(vulnerabilities)
        # If any CVE has EPSS ≥ 0.5, escalate action to quarantine
        high_epss = [v for v in vulnerabilities if v.get("epss", 0.0) >= 0.5]
        if high_epss:
            risk_score = min(risk_score + 10, 100)
            action = "quarantine"
            logger.warning(
                f"⚡ {len(high_epss)} high-EPSS CVE(s) on {ip} — escalating to quarantine"
            )

        # ── LAYER 6: RTSP Unauthenticated Stream Probe ────────────────────────
        if 554 in ports or 8554 in ports:
            try:
                from sin.scanner.rtsp_probe import rtsp_probe
                rtsp_port = 554 if 554 in ports else 8554
                rtsp_finding = rtsp_probe.probe(ip, rtsp_port, vendor=mfr)
                if rtsp_finding:
                    rtsp_finding.setdefault("epss", 0.0)
                    rtsp_finding.setdefault("priority_score", 0.0)
                    vulnerabilities.append(rtsp_finding)
                    risk_score = min(risk_score + 20, 100)
                    action = "quarantine"
                    logger.warning(f"📹 RTSP OPEN on {ip}:{rtsp_port} — unauthenticated stream confirmed")
            except Exception as e:
                logger.debug(f"RTSP probe error for {ip}: {e}")

        # ── LAYER 9: Default credential check ───────────────────────────────
        try:
            cred_finding = _creds.check(device_data)
            if cred_finding:
                vulnerabilities.append(cred_finding)
                risk_score = min(risk_score + 30, 100)
                action = "quarantine"
                logger.warning(f"🔑 DEFAULT_CREDS_FOUND on {ip} — quarantine escalated")
        except Exception as e:
            logger.debug(f"Cred check error for {ip}: {e}")

        # ── LAYER 8: Remediation roadmap ────────────────────────────────────
        vulnerabilities = [_attach_remediation(v) for v in vulnerabilities]

        logger.info(f"✅ Brain Decision for {ip} | Risk: {risk_score} | Action: {action} | KEV hits: {len(kev_hits)}")
        return vulnerabilities, risk_score, action
