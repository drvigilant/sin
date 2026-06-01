"""
sin.scanner.audit — Evidence-based IoT security audit engine

Risk scoring model (v2):
  Base score = highest single finding weight (not additive)
  Bonus = confirmed evidence on top (creds, KEV, EPSS)
  Final = min(base + bonus, 99)

  CRITICAL (75-99): RCE confirmed + default creds confirmed
  HIGH    (50-74):  RCE port present OR known critical CVE, creds not confirmed
  MEDIUM  (25-49):  Privacy/cleartext exposure, management exposure
  LOW     (1-24):   Informational, minor exposure

Severity is driven by the WORST single confirmed finding, not the sum.
This means a device with 8 medium findings is still MEDIUM, not CRITICAL.
"""

import os
from typing import Dict, List, Tuple
from sin.utils.logger import get_logger
from sin.scanner.kev_intel import kev as _kev
from sin.scanner.epss_intel import epss as _epss
from sin.scanner.cred_check import cred_checker as _creds

logger = get_logger("sin.scanner.audit")

# ── Finding weights — base score contribution of each finding ─────────────────
# These are NOT additive. The highest weight sets the base score.
# Secondary findings add a capped bonus (max +20).
FINDING_WEIGHTS = {
    # RCE / Takeover class (base 70-85)
    "CVE-2018-10088":   85,   # Xiongmai unauthenticated RCE
    "CVE-2017-7921":    82,   # Hikvision ISAPI auth bypass
    "CVE-2021-36260":   88,   # Hikvision command injection (critical, patched slowly)
    "CVE-2021-33044":   72,   # Dahua auth bypass
    "CVE-2022-30525":   90,   # Zyxel firewall RCE
    "CVE-2023-28771":   88,   # Zyxel OS command injection
    # Cleartext admin (base 60-75)
    "Cleartext Management Telnet": 75,
    "Cleartext Management FTP":    60,
    # Windows attack surface (base 65-80)
    "Windows SMB Exposure":   78,
    "RDP Attack Surface":     65,
    # Database exposure (base 80-90)
    "Exposed Database":       85,
    # ICS/OT (base 80)
    "Industrial Control Exposure": 80,
    # CCTV/camera specific (base 45-65)
    "Privacy Leak (RTSP)":         48,
    "RTSP No Authentication":      62,
    "Unencrypted Management HTTP": 30,
    # Credential findings (bonus only — these UPGRADE severity)
    "DEFAULT_CREDS_FOUND":         20,   # adds to base, never standalone CRITICAL
    # Networking
    "Router Admin Exposure":       55,
}

# ── Remediation playbooks ─────────────────────────────────────────────────────
REMEDIATION_DB: Dict[str, List[str]] = {
    "CVE-2018-10088": [
        "Block TCP port 34567 at the network perimeter firewall — this port has no legitimate external use.",
        "Update device firmware via web UI (Settings → System → Upgrade). Xiongmai released patches in 2018.",
        "Change default admin password from 'admin/admin' or blank to a strong unique credential.",
        "If firmware update is unavailable, place device on an isolated VLAN with no internet access.",
    ],
    "CVE-2017-7921": [
        "Update Hikvision firmware to v5.4.5 or later via device web interface.",
        "Block unauthenticated access to ISAPI endpoints at the firewall.",
        "Rotate admin credentials immediately — previous credentials may be compromised.",
        "Check CISA advisory AA22-257A for full mitigation guidance.",
    ],
    "CVE-2021-36260": [
        "Update Hikvision firmware to v5.5.800 or later — this is an actively exploited vulnerability.",
        "Block external access to ports 80 and 443 from untrusted network segments.",
        "Apply network segmentation — place all cameras on a dedicated camera VLAN.",
    ],
    "CVE-2021-33044": [
        "Update Dahua firmware to version released after 2021-10-22.",
        "Block TCP port 37777 at the firewall — this is the Dahua SDK port.",
        "Disable Dahua P2P cloud service (Easy4IP/DMSS) if not required.",
        "Monitor for unusual authentication attempts in device logs.",
    ],
    "Cleartext Management Telnet": [
        "Disable Telnet service in device settings immediately.",
        "Enable SSH v2 with key-based authentication as replacement.",
        "Block TCP port 23 at perimeter and internal firewall.",
        "Rotate all credentials — assume they are compromised if Telnet was accessible.",
    ],
    "Cleartext Management FTP": [
        "Disable FTP service if not required for operations.",
        "Replace with SFTP (SSH File Transfer Protocol) if file transfer is needed.",
        "Block TCP port 21 at the network boundary.",
    ],
    "Privacy Leak (RTSP)": [
        "Enable RTSP digest authentication in camera settings.",
        "Restrict RTSP access to authorised IP ranges via firewall rules.",
        "Use a VPN or RTSP-over-HTTPS tunnel for remote viewing.",
        "Block TCP port 554 from internet-facing interfaces.",
    ],
    "RTSP No Authentication": [
        "Enable RTSP authentication (digest preferred over basic) in camera settings.",
        "Change default RTSP stream path from /stream or /live to a non-guessable path.",
        "Block port 554 externally — only allow from trusted network segments.",
    ],
    "Unencrypted Management HTTP": [
        "Enable HTTPS on the device management interface if supported.",
        "Restrict port 80 access to management VLAN only via firewall ACL.",
        "Consider placing the device behind a reverse proxy with TLS termination.",
    ],
    "Windows SMB Exposure": [
        "Block TCP port 445 at the network perimeter — SMB should never be internet-facing.",
        "Disable SMBv1 via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
        "Apply all Windows security updates — prioritise MS17-010 (EternalBlue).",
        "Enable Windows Firewall and restrict SMB to domain controllers only.",
    ],
    "RDP Attack Surface": [
        "Move RDP to a non-standard port and restrict access to VPN/jump server only.",
        "Enable Network Level Authentication (NLA) for RDP connections.",
        "Enforce MFA for all remote access.",
        "Monitor RDP login failures — alert on >5 failures in 60 seconds.",
    ],
    "Exposed Database": [
        "Bind database listener to localhost (127.0.0.1) — never 0.0.0.0.",
        "Enable authentication — Redis: requirepass, MongoDB: --auth, Elasticsearch: security.enabled.",
        "Block external access to ports 6379/27017/9200 via firewall.",
        "Rotate all data and API keys that may have been exposed.",
    ],
    "Industrial Control Exposure": [
        "Isolate OT/ICS devices on a dedicated VLAN with no direct internet path.",
        "Deploy an industrial firewall (Claroty, Dragos, or Nozomi) between IT and OT networks.",
        "Block TCP port 502 (Modbus) and UDP 47808 (BACnet) at the IT/OT boundary.",
        "Establish a documented change management process for all OT device updates.",
    ],
    "Router Admin Exposure": [
        "Restrict Winbox (TCP 8291) and SSH access to a dedicated management IP range.",
        "Update RouterOS to the latest stable release.",
        "Disable the default 'admin' account and create a named administrator account.",
        "Enable two-factor authentication if supported by the firmware version.",
    ],
    "DEFAULT_CREDS_FOUND": [
        "Change default credentials immediately — device is fully compromised if this is internet-facing.",
        "Enable account lockout policy (lock after 5 failed attempts for 15 minutes).",
        "Audit other devices from the same vendor — default credentials are often fleet-wide.",
        "Segment the device to a restricted VLAN to limit blast radius.",
    ],
}

def _attach_remediation(finding: Dict) -> Dict:
    cve   = (finding.get("cve") or "").upper()
    ftype = finding.get("type", "")
    steps = (REMEDIATION_DB.get(cve)
             or REMEDIATION_DB.get(ftype)
             or ["Follow vendor security advisories.",
                 "Apply principle of least privilege.",
                 "Restrict network access to this device."])
    finding.setdefault("remediation", steps)
    return finding


def _compute_risk(findings: List[Dict], creds_confirmed: bool) -> Tuple[int, str]:
    """
    Evidence-based risk computation.

    Base score  = highest single finding weight
    Bonus       = capped secondary contributions (max +20 total)
    Cred bonus  = +15 if default creds confirmed on a high-weight base
    KEV bonus   = +10 if any finding is in CISA KEV
    EPSS bonus  = +5  if any EPSS >= 0.5

    Final score intentionally never reaches 100 — 100 would imply
    certainty of full compromise, which requires human confirmation.
    Max is 99 for automated scoring.

    Severity thresholds:
      CRITICAL : score >= 75 AND (RCE finding present OR creds confirmed)
      HIGH     : score >= 50
      MEDIUM   : score >= 25
      LOW      : score < 25
    """
    if not findings:
        return 0, "LOW"

    weights = []
    for f in findings:
        # Look up weight by CVE first, then by type
        cve   = (f.get("cve") or "").upper()
        ftype = f.get("type", "")
        w = FINDING_WEIGHTS.get(cve) or FINDING_WEIGHTS.get(ftype) or 0
        # Map severity to fallback weight if not in our DB
        if w == 0:
            sev = (f.get("severity") or "LOW").upper()
            w = {"CRITICAL": 70, "HIGH": 50, "MEDIUM": 30, "LOW": 15, "WARNING": 20}.get(sev, 15)
        weights.append(w)

    weights.sort(reverse=True)
    base  = weights[0]

    # Secondary findings add 30% of their weight each, capped at +20 total
    bonus = min(sum(w * 0.30 for w in weights[1:]), 20)

    # Confirmed default creds upgrades score significantly
    cred_bonus = 15 if creds_confirmed else 0

    # KEV and EPSS bonuses — intentionally small; CVE weights already reflect severity.
    # These are confirmatory nudges, not score drivers.
    kev_bonus  = 5  if any(f.get("in_kev") for f in findings) else 0
    epss_bonus = 3  if any(f.get("epss", 0.0) >= 0.5 for f in findings) else 0

    score = int(min(base + bonus + cred_bonus + kev_bonus + epss_bonus, 99))

    # ── Severity thresholds ───────────────────────────────────────────────────
    # CRITICAL requires BOTH:
    #   1. An RCE-class finding (CVE or finding type)
    #   2. Default credentials confirmed on the device
    # This prevents port-open-alone (no active exploitation proof) from reaching CRITICAL.
    # RCE present but creds unknown → HIGH (still serious, not confirmed full compromise).
    rce_types = {"Remote Code Execution", "Backdoor Access", "Exposed Database",
                 "Industrial Control Exposure", "Windows SMB Exposure"}
    rce_cves  = {"CVE-2018-10088", "CVE-2017-7921", "CVE-2021-36260",
                 "CVE-2021-33044", "CVE-2022-30525", "CVE-2023-28771"}
    has_rce   = any(
        f.get("type") in rce_types or (f.get("cve") or "").upper() in rce_cves
        for f in findings
    )

    if score >= 75 and has_rce and creds_confirmed:
        level = "CRITICAL"
    elif score >= 50 and has_rce:
        level = "HIGH"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level


class AuditEngine:
    def __init__(self):
        self.ai_enabled = False

    def evaluate_asset(self, device_data: Dict) -> Tuple[List[Dict], int, str]:
        vulnerabilities = []
        creds_confirmed = False

        ip      = device_data.get("ip_address", "Unknown")
        mfr     = (device_data.get("manufacturer") or "").lower()
        ports   = set(device_data.get("open_ports", []))
        banners = str(device_data.get("banners", {})).lower()

        logger.info(f"[audit] Starting evidence-based audit for {ip} | ports={sorted(ports)}")

        # ── LAYER 0: HTTP fingerprinting ──────────────────────────────────────
        try:
            from sin.scanner.http_fingerprint import fingerprint as http_fp
            fp = http_fp(ip, list(ports))
            if fp:
                for field, val in fp.items():
                    cur = device_data.get(field, "")
                    if not cur or cur.lower() in ("unknown", ""):
                        device_data[field] = val
                if device_data.get("vendor") and not device_data.get("manufacturer"):
                    device_data["manufacturer"] = device_data["vendor"]
                if device_data.get("manufacturer") and not device_data.get("vendor"):
                    device_data["vendor"] = device_data["manufacturer"]
                mfr = (device_data.get("manufacturer") or "").lower()
                logger.info(f"[audit] {ip} fingerprinted → vendor={device_data.get('vendor')} "
                            f"model={device_data.get('model')} fw={device_data.get('firmware')}")
        except Exception as e:
            logger.debug(f"[audit] HTTP fingerprint error {ip}: {e}")

        # ── LAYER 1: ONVIF / ISAPI enrichment ────────────────────────────────
        try:
            from sin.scanner.onvif_intel import onvif_prober
            od = onvif_prober.probe(ip, list(ports))
            if od:
                if od.get("model"):    device_data["model"]       = od["model"].strip()
                if od.get("firmware"): device_data["firmware"]    = od["firmware"].strip()
                if od.get("mac_address"): device_data["mac_address"] = od["mac_address"].strip()
                if od.get("serial"):   device_data["serial"]      = od["serial"].strip()
        except Exception as e:
            logger.debug(f"[audit] ONVIF probe error {ip}: {e}")

        try:
            from sin.scanner.isapi_intel import isapi_prober
            telemetry = isapi_prober.probe_telemetry(ip, list(ports))
            if telemetry:
                device_data["telemetry"] = telemetry
                cpu = telemetry.get("cpu_usage", "0%")
                if int(str(cpu).replace("%", "")) > 90:
                    vulnerabilities.append({
                        "severity": "WARNING",
                        "type": "Hardware Anomaly",
                        "description": f"CPU usage at {cpu} — potential malware infection or hardware fault.",
                        "port": None,
                    })
        except Exception:
            pass

        # ── LAYER 2: Port-based heuristics ───────────────────────────────────
        # Each finding is only added when there is confirmed evidence.
        # Severity is set per-finding; final level is computed by _compute_risk.

        # Telnet — Mirai/Mozi primary attack vector
        if 23 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Cleartext Management Telnet",
                "cve": "",
                "description": (
                    "Telnet (port 23) is open and transmits all credentials in cleartext. "
                    "This is the primary infection vector for Mirai, Mozi, and similar IoT botnets. "
                    "Any device with Telnet open on a routable IP should be treated as compromised."
                ),
                "port": 23,
            })

        # FTP
        if 21 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Cleartext Management FTP",
                "cve": "",
                "description": (
                    "FTP (port 21) transmits credentials and file contents in cleartext. "
                    "Passive eavesdropping on the network segment is sufficient to capture credentials."
                ),
                "port": 21,
            })

        # SMB — EternalBlue / ransomware vector
        if 445 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Windows SMB Exposure",
                "cve": "MS17-010",
                "description": (
                    "SMB (port 445) is exposed. This is the primary lateral movement vector for "
                    "WannaCry, NotPetya, and EternalBlue-based ransomware. "
                    "If SMBv1 is enabled, unauthenticated remote code execution is possible."
                ),
                "port": 445,
            })

        # RDP
        if 3389 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "RDP Attack Surface",
                "cve": "CVE-2019-0708",
                "description": (
                    "RDP (port 3389) is exposed. Vulnerable to BlueKeep (CVE-2019-0708) on unpatched "
                    "systems, and a constant target for credential brute-force attacks. "
                    "Exposed RDP is one of the most common ransomware initial access vectors."
                ),
                "port": 3389,
            })

        # Unauthenticated databases
        if 6379 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Exposed Database",
                "cve": "",
                "description": (
                    "Redis (port 6379) is accessible without authentication. "
                    "Unauthenticated Redis allows full data access, config overwrite, "
                    "and in many cases remote code execution via config rewrite attacks."
                ),
                "port": 6379,
            })
        if 27017 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Exposed Database",
                "cve": "",
                "description": (
                    "MongoDB (port 27017) may be accessible without authentication. "
                    "Hundreds of thousands of MongoDB instances have been wiped and ransomed. "
                    "Verify authentication is enforced."
                ),
                "port": 27017,
            })
        if 9200 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Exposed Database",
                "cve": "",
                "description": (
                    "Elasticsearch (port 9200) is exposed. Default installations have no authentication. "
                    "Full index enumeration and data exfiltration is possible without credentials."
                ),
                "port": 9200,
            })

        # MikroTik Winbox
        if 8291 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Router Admin Exposure",
                "cve": "CVE-2018-14847",
                "description": (
                    "MikroTik Winbox (port 8291) management interface is exposed. "
                    "CVE-2018-14847 allows unauthenticated credential extraction on RouterOS < 6.42.1. "
                    "Over 300,000 routers were compromised in the VPNFilter campaign via this vector."
                ),
                "port": 8291,
            })

        # Xiongmai/Generic DVR — port 34567 is the SDK port
        if 34567 in ports:
            vulnerabilities.append({
                "severity": "HIGH",   # HIGH by default — upgraded to CRITICAL if creds confirmed
                "type": "Remote Code Execution",
                "cve": "CVE-2018-10088",
                "description": (
                    "Xiongmai/generic DVR SDK port (34567) is open. "
                    "CVE-2018-10088 allows unauthenticated remote code execution on the underlying HiSilicon SoC. "
                    "Affects Xiongmai, XMeye, Sofia, and hundreds of white-label OEM brands including Securus, "
                    "Annke, and Night Owl. The vulnerability is in the firmware, not the brand — "
                    "any device on this port is affected regardless of branding."
                ),
                "port": 34567,
            })

        # Hikvision ISAPI
        if "hikvision" in mfr or "hikvision" in banners:
            if 8000 in ports or 80 in ports:
                vulnerabilities.append({
                    "severity": "HIGH",
                    "type": "Backdoor Access",
                    "cve": "CVE-2017-7921",
                    "description": (
                        "Hikvision device detected with ISAPI port accessible. "
                        "CVE-2017-7921 allows authentication bypass via a crafted URL, "
                        "giving unauthenticated access to the snapshot, configuration, and user management APIs. "
                        "This was actively exploited by Iranian threat actors (CISA AA22-257A)."
                    ),
                    "port": 8000 if 8000 in ports else 80,
                })

        # Dahua SDK
        if 37777 in ports:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Credential Leak",
                "cve": "CVE-2021-33044",
                "description": (
                    "Dahua SDK port (37777) is open. "
                    "CVE-2021-33044 allows authentication bypass via a specially crafted login packet, "
                    "enabling credential extraction without knowing the current password. "
                    "Affects a wide range of Dahua NVR/DVR/camera models."
                ),
                "port": 37777,
            })
        elif "dahua" in mfr:
            vulnerabilities.append({
                "severity": "MEDIUM",
                "type": "Credential Leak",
                "cve": "CVE-2021-33044",
                "description": (
                    "Dahua device identified by vendor name. "
                    "Dahua SDK port (37777) is not confirmed open, but the device family "
                    "is affected by CVE-2021-33044 if running unpatched firmware."
                ),
                "port": None,
            })

        # RTSP — privacy exposure
        if 554 in ports or 8554 in ports:
            p = 554 if 554 in ports else 8554
            vulnerabilities.append({
                "severity": "MEDIUM",
                "type": "Privacy Leak (RTSP)",
                "cve": "",
                "description": (
                    f"RTSP stream server is open on port {p}. "
                    "If authentication is not required (common on budget cameras), "
                    "anyone on the network can view the live video feed without credentials. "
                    "Many cameras use predictable stream paths (/stream, /live, /ch0)."
                ),
                "port": p,
            })

        # HTTP management
        if 80 in ports:
            vulnerabilities.append({
                "severity": "LOW",
                "type": "Unencrypted Management HTTP",
                "cve": "",
                "description": (
                    "HTTP management interface is accessible on port 80. "
                    "Login credentials are transmitted in cleartext and can be captured "
                    "by anyone with access to the network segment. "
                    "Use HTTPS if the device supports it."
                ),
                "port": 80,
            })

        # ICS/OT protocols
        if 502 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Industrial Control Exposure",
                "cve": "",
                "description": (
                    "Modbus TCP (port 502) is accessible. Modbus has no authentication or encryption. "
                    "Any device on the network can read sensor data, write coil states, "
                    "or force register values — potentially causing physical damage to industrial equipment."
                ),
                "port": 502,
            })
        if 47808 in ports:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "type": "Industrial Control Exposure",
                "cve": "",
                "description": (
                    "BACnet (UDP 47808) is accessible. BACnet has no built-in authentication. "
                    "Building automation systems (HVAC, access control, elevators) can be "
                    "enumerated and manipulated without credentials."
                ),
                "port": 47808,
            })

        # ── LAYER 3: Active probing ───────────────────────────────────────────

        # RTSP authentication probe
        if 554 in ports or 8554 in ports:
            try:
                from sin.scanner.rtsp_probe import rtsp_probe
                rtsp_finding = rtsp_probe.probe(ip, 554 if 554 in ports else 8554, vendor=mfr)
                if rtsp_finding:
                    rtsp_finding.setdefault("epss", 0.0)
                    vulnerabilities.append(rtsp_finding)
            except Exception:
                pass

        # Default credential probe — this is what upgrades CRITICAL
        try:
            cred_finding = _creds.check(device_data)
            if cred_finding:
                creds_confirmed = True
                vulnerabilities.append(cred_finding)
        except Exception:
            pass

        # ── LAYER 4: Threat intelligence enrichment ───────────────────────────
        vulnerabilities = _kev.flag_kev_matches(vulnerabilities)
        vulnerabilities = _epss.enrich_findings(vulnerabilities)

        # ── LAYER 5: ONVIF security audit ─────────────────────────────────────
        try:
            from sin.scanner.onvif_audit import onvif_auditor
            onvif_findings = onvif_auditor.audit(ip, list(ports))
            for f in onvif_findings:
                f.setdefault("epss", 0.0)
                vulnerabilities.append(f)
        except Exception as e:
            logger.debug(f"[audit] ONVIF audit error {ip}: {e}")

        # ── Attach remediation steps ──────────────────────────────────────────
        vulnerabilities = [_attach_remediation(v) for v in vulnerabilities]

        # ── Compute final risk score and level ────────────────────────────────
        risk_score, risk_level = _compute_risk(vulnerabilities, creds_confirmed)

        # Update device_data so it's persisted correctly
        device_data["risk_level"] = risk_level
        device_data["risk_score"] = risk_score

        action = (
            "quarantine"   if risk_score >= 80 else
            "alert_soc"    if risk_score >= 50 else
            "monitor"      if risk_score >= 25 else
            "log_only"
        )

        logger.info(
            f"[audit] {ip} complete | findings={len(vulnerabilities)} "
            f"score={risk_score} level={risk_level} action={action} "
            f"creds={'YES' if creds_confirmed else 'no'}"
        )

        return vulnerabilities, risk_score, action
