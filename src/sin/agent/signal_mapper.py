from typing import List, Dict

PORT_SIGNATURE_MAP = {
    23: "TELNET", 21: "FTP", 80: "HTTP_ONLY", 554: "RTSP",
    1883: "MQTT", 502: "MODBUS", 6379: "REDIS", 27017: "MONGODB",
    3389: "RDP", 161: "SNMP", 7547: "TR069", 37777: "DAHUA_SDK", 34567: "DVR_WEB",
}

def map_vulnerabilities(raw_vulns):
    mapped = []
    for v in raw_vulns:
        if v.get("type") or v.get("description"):
            mapped.append(v)
        elif v.get("port"):
            sig_id = PORT_SIGNATURE_MAP.get(v["port"])
            if sig_id:
                mapped.append({"sig_id": sig_id, "severity": v.get("severity", "MEDIUM")})
    return mapped

def normalize_host(host):
    raw_vulns = host.get("vulnerabilities", [])
    host["vulnerabilities"] = map_vulnerabilities(raw_vulns)
    if "_packet_signals" not in host:
        host["_packet_signals"] = []
    return host
