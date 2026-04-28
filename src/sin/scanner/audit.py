import os
from typing import Dict, List, Tuple
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.audit")

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

        logger.info(f"✅ Brain Decision for {ip} | Risk: {risk_score} | Action: {action}")
        return vulnerabilities, risk_score, action
