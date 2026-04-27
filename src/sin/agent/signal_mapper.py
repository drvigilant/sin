"""
sin.agent.signal_mapper
───────────────────────
Converts raw scanner output into DecisionEngine-compatible signals.
"""

from typing import List, Dict

# Port → signature mapping
PORT_SIGNATURE_MAP = {
    23: "TELNET",
    21: "FTP",
    80: "HTTP_ONLY",
    554: "RTSP",
    1883: "MQTT",
    502: "MODBUS",
    6379: "REDIS",
    27017: "MONGODB",
    3389: "RDP",
    161: "SNMP",
    7547: "TR069",
    37777: "DAHUA_SDK",
    34567: "DVR_WEB",
}


def map_vulnerabilities(raw_vulns: List[Dict]) -> List[Dict]:
    """
    Convert raw scanner findings → DecisionEngine format
    Expected input example:
        {"port": 23, "service": "telnet"}
    Output:
        {"sig_id": "TELNET", "severity": "MEDIUM"}
    """
    mapped = []

    for v in raw_vulns:
        port = v.get("port")
        sig_id = PORT_SIGNATURE_MAP.get(port)

        if not sig_id:
            continue

        mapped.append({
            "sig_id": sig_id,
            "severity": v.get("severity", "MEDIUM")
        })

    return mapped


def normalize_host(host: Dict) -> Dict:
    """
    Normalize full host object before DecisionEngine
    """
    raw_vulns = host.get("vulnerabilities", [])
    host["vulnerabilities"] = map_vulnerabilities(raw_vulns)

    # Ensure packet signals exist
    if "_packet_signals" not in host:
        host["_packet_signals"] = []

    return host
