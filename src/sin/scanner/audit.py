import os
from typing import Dict, List, Tuple
from sin.utils.logger import get_logger
from sin.scanner.kev_intel import kev as _kev
from sin.scanner.epss_intel import epss as _epss
from sin.scanner.cred_check import cred_checker as _creds

logger = get_logger("sin.scanner.audit")

# ── Remediation playbooks ──────────────────────────────────────────────────────
REMEDIATION_DB: Dict[str, List[str]] = {
    "CVE-2018-10088": ["Block TCP port 34567 at firewall.", "Update Xiongmai firmware via web UI.", "Change default admin password."],
    "CVE-2017-7921": ["Update Hikvision firmware to v5.4.5+.", "Block unauth access to ISAPI.", "Rotate admin credentials."],
    "CVE-2021-36260": ["Update Hikvision firmware to v5.5.800+.", "Block network access to port 80/443 from untrusted segments."],
    "CVE-2021-33044": ["Update Dahua firmware (2021-10-22+).", "Block TCP port 37777.", "Disable Dahua P2P cloud service."],
    "Cleartext Management": ["Disable Telnet immediately.", "Enable SSH v2 with RSA keys.", "Block TCP port 23 at perimeter firewall."],
    "Privacy Leak (RTSP)": ["Enable RTSP authentication.", "Tunnel RTSP via HTTPS.", "Block TCP ports 554/8554 from untrusted networks."],
    "Industrial Control Exposure": ["Isolate on dedicated OT VLAN.", "Block TCP port 502/UDP 47808 at boundary.", "Deploy ICS firewall."],
    "Windows SMB Exposure": ["Block TCP 445 at perimeter.", "Disable SMBv1 via PowerShell.", "Apply latest Windows Security Rollups."],
    "RDP Attack Surface": ["Block TCP 3389 at perimeter.", "Enforce Network Level Authentication (NLA).", "Deploy MFA for remote access."],
    "Exposed Database": ["Bind database to localhost (127.0.0.1) only.", "Enable authentication.", "Block external access to port 6379/27017/9200."],
    "Router Admin Exposure": ["Restrict Winbox/SSH access to management IPs.", "Update RouterOS.", "Disable default 'admin' user."],
    "DEFAULT_CREDS_FOUND": ["Change default credentials immediately.", "Enable account lockout.", "Segment device to restrict blast radius."],
}

def _attach_remediation(finding: Dict) -> Dict:
    cve = (finding.get("cve") or "").upper()
    ftype = finding.get("type", "")
    steps = REMEDIATION_DB.get(cve) or REMEDIATION_DB.get(ftype) or ["Follow vendor security advisories and apply the principle of least privilege."]
    finding.setdefault("remediation", steps)
    return finding

class AuditEngine:
    def __init__(self):
        self.ai_enabled = False

    def evaluate_asset(self, device_data: Dict) -> Tuple[List[Dict], int, str]:
        vulnerabilities = []
        risk_score = 0

        ip = device_data.get("ip_address", "Unknown")
        mfr = (device_data.get("manufacturer") or "").lower()
        model = (device_data.get("model") or "Unknown")
        ports = set(device_data.get("open_ports", []))
        banners = str(device_data.get("banners", {})).lower()
        discovery = device_data.get("discovery_method", "TCP Scan")

        logger.info(f"🔎 Brain conducting deep heuristic audit for {ip} [{mfr}]...")

        # --- 🛡️ LAYER 1: DEEP ACTIVE INTERROGATION (ONVIF/ISAPI) ---
        try:
            from sin.scanner.onvif_intel import onvif_prober
            onvif_data = onvif_prober.probe(ip, list(ports))
            if onvif_data:
                if onvif_data.get("manufacturer"): device_data["manufacturer"] = onvif_data["manufacturer"].strip()
                if onvif_data.get("model"): device_data["model"] = onvif_data["model"].strip()
                if onvif_data.get("firmware"): device_data["firmware"] = onvif_data["firmware"].strip()
                if onvif_data.get("mac_address"): device_data["mac_address"] = onvif_data["mac_address"].strip()
                if onvif_data.get("serial"): device_data["serial"] = onvif_data["serial"].strip()
        except Exception as e:
            logger.debug(f"ONVIF probe error for {ip}: {e}")

        try:
            from sin.scanner.isapi_intel import isapi_prober
            telemetry = isapi_prober.probe_telemetry(ip, list(ports))
            if telemetry:
                device_data["telemetry"] = telemetry
                if "cpu_usage" in telemetry and int(telemetry["cpu_usage"].replace("%", "")) > 90:
                    vulnerabilities.append({"severity": "WARNING", "type": "Hardware Anomaly", "description": "CPU Usage critically high. Potential malware infection."})
                    risk_score += 15
        except Exception:
            pass

        # --- 🛡️ LAYER 2: 90% HEURISTIC COVERAGE (IoT + IT + OT) ---
        
        # 1. Cleartext / Admin Risks
        if 23 in ports:
            vulnerabilities.append({"severity": "CRITICAL", "type": "Cleartext Management", "description": "Telnet exposed. Target for Mirai/Mozi botnets."})
            risk_score += 95
        if 21 in ports:
            vulnerabilities.append({"severity": "HIGH", "type": "Cleartext Management", "description": "FTP exposed. Cleartext credential sniffing risk."})
            risk_score += 60
        
        # 2. Windows IT Exploits (Ransomware vectors)
        if 445 in ports:
            vulnerabilities.append({"severity": "CRITICAL", "type": "Windows SMB Exposure", "description": "SMB exposed. Extreme risk of EternalBlue/WannaCry lateral movement."})
            risk_score += 85
        if 3389 in ports:
            vulnerabilities.append({"severity": "HIGH", "type": "RDP Attack Surface", "description": "RDP exposed. Target for BlueKeep exploits and credential brute-forcing."})
            risk_score += 75

        # 3. Database / Big Data Leaks
        if 6379 in ports or 27017 in ports or 9200 in ports:
            vulnerabilities.append({"severity": "CRITICAL", "type": "Exposed Database", "description": "Unauthenticated database port exposed (Redis/Mongo/Elastic). Massive data exfiltration risk."})
            risk_score += 90

        # 4. Networking / Infrastructure
        if 8291 in ports: # MikroTik Winbox
            vulnerabilities.append({"severity": "HIGH", "type": "Router Admin Exposure", "description": "MikroTik Winbox management exposed. High risk of router hijack."})
            risk_score += 70

        # 5. CCTV / NVR Specific
        if "xiongmai" in mfr or "h264dvr" in banners:
            if 34567 in ports:
                vulnerabilities.append({"severity": "CRITICAL", "type": "Remote Code Execution", "cve": "CVE-2018-10088", "description": "Xiongmai DVR service unauthenticated."})
                risk_score += 90
        if "hikvision" in mfr or "hikvision-httppreview" in banners:
            if 8000 in ports or 80 in ports:
                vulnerabilities.append({"severity": "CRITICAL", "type": "Backdoor Access", "cve": "CVE-2017-7921", "description": "Potential Hikvision backdoor."})
                risk_score += 85
        if "dahua" in mfr or 37777 in ports:
            vulnerabilities.append({"severity": "HIGH", "type": "Credential Leak", "cve": "CVE-2021-33044", "description": "Dahua auth bypass vulnerability."})
            risk_score += 75
        if 554 in ports or 8554 in ports:
            vulnerabilities.append({"severity": "HIGH", "type": "Privacy Leak (RTSP)", "description": "Unencrypted video stream detected."})
            risk_score += 50

        # 6. ICS / OT Risks
        if 502 in ports or 47808 in ports:
            vulnerabilities.append({"severity": "CRITICAL", "type": "Industrial Control Exposure", "description": "OT/ICS protocol (Modbus/BACnet) detected on standard network."})
            risk_score += 100

        # --- 🛡️ LAYER 3: DYNAMIC PROBING & INTEL ---
        risk_score = min(risk_score, 100)

        # RTSP Probe
        if 554 in ports or 8554 in ports:
            try:
                from sin.scanner.rtsp_probe import rtsp_probe
                rtsp_finding = rtsp_probe.probe(ip, 554 if 554 in ports else 8554, vendor=mfr)
                if rtsp_finding:
                    rtsp_finding.setdefault("epss", 0.0)
                    vulnerabilities.append(rtsp_finding)
                    risk_score = min(risk_score + 20, 100)
            except Exception:
                pass

        # Default Credential Probe
        try:
            cred_finding = _creds.check(device_data)
            if cred_finding:
                vulnerabilities.append(cred_finding)
                risk_score = min(risk_score + 30, 100)
        except Exception:
            pass

        # EPSS & KEV Intel Enrichment
        vulnerabilities = _kev.flag_kev_matches(vulnerabilities)
        kev_hits = [v for v in vulnerabilities if v.get("in_kev")]
        if kev_hits: risk_score = min(risk_score + 15, 100)

        vulnerabilities = _epss.enrich_findings(vulnerabilities)
        if any(v.get("epss", 0.0) >= 0.5 for v in vulnerabilities): risk_score = min(risk_score + 10, 100)

        # ── LAYER 4: ONVIF SECURITY AUDIT ─────────────────────────────────────
        try:
            from sin.scanner.onvif_audit import onvif_auditor
            onvif_findings = onvif_auditor.audit(ip, list(ports))
            for f in onvif_findings:
                f.setdefault("epss", 0.0)
                vulnerabilities.append(f)
        except Exception as e:
            logger.warning(f"ONVIF audit error for {ip}: {e}")

        vulnerabilities = [_attach_remediation(v) for v in vulnerabilities]

        # Action Verdict
        action = "quarantine" if risk_score >= 80 else "alert_soc" if risk_score >= 50 else "monitor" if risk_score >= 20 else "log_only"

        return vulnerabilities, risk_score, action
