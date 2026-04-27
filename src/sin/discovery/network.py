"""
sin.discovery.network v8.0 — Go-powered IoT Scanner
Calls the compiled Go binary for speed, falls back to Python if unavailable.
"""
import json
import os
import socket
import subprocess
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.discovery.network")

# Path to compiled Go scanner binary inside the container
GO_SCANNER_PATH = os.getenv("SIN_SCANNER_PATH", "/app/bin/sin-scanner")

# IoT ports for Python fallback
IOT_PORTS = [
    80, 443, 554, 8554, 8080, 8888, 8000,
    37777, 34567, 1883, 8883, 5683, 1900,
    502, 47808, 21, 22, 23, 8443,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
    554: "RTSP", 1883: "MQTT", 1900: "UPnP", 5683: "CoAP",
    8000: "HTTP-Hikvision", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8554: "RTSP-Alt", 8883: "MQTT-TLS", 8888: "HTTP-Alt2",
    37777: "Dahua-SDK", 34567: "DVR-Web", 47808: "BACnet", 502: "Modbus",
}

NON_IOT_PORTS_ONLY = {445, 3389, 5985, 139, 135}
CAM_VENDORS = {"hikvision", "dahua", "axis", "vivotek", "hanwha", "uniview", "reolink", "amcrest"}


class NetworkDiscovery:
    def execute_subnet_scan(self, subnet_cidr: str = None) -> List[Dict]:
        if not subnet_cidr:
            subnet_cidr = self._get_local_subnet()

        # Try Go scanner first
        if os.path.exists(GO_SCANNER_PATH):
            logger.info(f"🚀 Go scanner detected. Running high-speed scan on {subnet_cidr}.0/24")
            result = self._run_go_scanner(subnet_cidr)
            if result is not None:
                logger.info(f"✅ Go scanner found {len(result)} IoT devices.")
                return result
            logger.warning("Go scanner failed, falling back to Python scanner.")

        # Python fallback
        logger.info(f"🐍 Python scanner running on {subnet_cidr}.0/24")
        return self._python_scan(subnet_cidr)

    # ── Go Scanner ────────────────────────────────────────────────────────

    def _run_go_scanner(self, subnet: str) -> Optional[List[Dict]]:
        try:
            result = subprocess.run(
                [GO_SCANNER_PATH, subnet],
                capture_output=True,
                text=True,
                timeout=180,  # 3 min max
            )
            if result.returncode != 0:
                logger.error(f"Go scanner error: {result.stderr[:200]}")
                return None

            devices = json.loads(result.stdout.strip())
            if not isinstance(devices, list):
                return None

            # Normalize fields for compatibility with rest of pipeline
            normalized = []
            for d in devices:
                d["protocol_hints"] = d.get("protocol_hints") or list(d.get("services", {}).values())
                d["vulnerabilities"] = d.get("vulnerabilities") or []
                normalized.append(d)

            return normalized

        except subprocess.TimeoutExpired:
            logger.error("Go scanner timed out after 3 minutes.")
            return None
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Go scanner output parse error: {e}")
            return None

    # ── Python Fallback Scanner ───────────────────────────────────────────

    def _python_scan(self, subnet: str) -> List[Dict]:
        targets = [f"{subnet}.{i}" for i in range(1, 255)]
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(self._scan_host, ip): ip for ip in targets}
            for future in concurrent.futures.as_completed(futures):
                try:
                    data = future.result()
                    if data:
                        results.append(data)
                except Exception:
                    pass

        logger.info(f"Python scanner found {len(results)} IoT devices.")
        return results

    def _scan_host(self, ip: str) -> Optional[Dict]:
        open_ports = self._scan_ports(ip)
        if not open_ports:
            return None

        ports_set = set(open_ports)

        # Drop pure Windows/PC devices
        if ports_set.issubset(NON_IOT_PORTS_ONLY):
            return None
        if len(ports_set) == 1 and 22 in ports_set:
            return None
        if ports_set.issubset({80, 443, 22, 8080}) and 554 not in ports_set:
            return None

        mac      = self._get_mac(ip)
        hostname = self._resolve_hostname(ip)
        vendor   = self._lookup_vendor(mac)

        http_banner = ""
        for p in [80, 8080, 8000, 8888]:
            if p in ports_set:
                http_banner = self._grab_http_banner(ip, p)
                if http_banner:
                    break

        if vendor == "Unknown" and http_banner:
            bl = http_banner.lower()
            for v in CAM_VENDORS:
                if v in bl:
                    vendor = v.capitalize()
                    break

        os_family, device_type = self._classify(open_ports, vendor, http_banner)

        services = {}
        protocols = []
        for p in open_ports:
            svc = PORT_SERVICES.get(p, f"TCP/{p}")
            services[str(p)] = svc
            protocols.append(svc)

        return {
            "ip_address":     ip,
            "status":         "online",
            "mac_address":    mac,
            "hostname":       hostname,
            "manufacturer":   vendor,
            "vendor":         vendor,
            "os_family":      os_family,
            "device_type":    device_type,
            "open_ports":     open_ports,
            "services":       services,
            "protocol_hints": protocols,
            "vulnerabilities": [],
            "last_seen":      datetime.now(timezone.utc).isoformat(),
            "scan_method":    "python-fallback",
        }

    def _scan_ports(self, ip: str) -> List[int]:
        open_ports = []

        def check(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex((ip, port)) == 0:
                        return port
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = ex.map(check, IOT_PORTS)

        return [p for p in results if p]

    def _get_mac(self, ip: str) -> str:
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00":
                            return mac.upper()
        except Exception:
            pass
        return "Unknown"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def _lookup_vendor(self, mac: str) -> str:
        OUI = {
            "C8F742": "Hikvision", "D8C4E9": "Hikvision", "A4143E": "Hikvision",
            "F48B32": "Hikvision", "BC0F9A": "Hikvision",
            "E0987B": "Dahua",    "3C1A57": "Dahua",    "704DB7": "Dahua",
            "ACCC8E": "Axis",     "B8A44E": "Axis",
            "4C5E0C": "MikroTik", "D4CA6D": "MikroTik", "E4A7A0": "MikroTik",
            "788A20": "Ubiquiti", "E063DA": "Ubiquiti",
            "B0487A": "TP-Link",  "F81A67": "TP-Link",
            "EC7176": "Reolink",  "DCEF09": "Amcrest",
        }
        clean = mac.replace(":", "").replace("-", "").upper()
        if len(clean) >= 6:
            return OUI.get(clean[:6], "Unknown")
        return "Unknown"

    def _grab_http_banner(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip, port))
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                resp = s.recv(1024).decode(errors="ignore")
                for line in resp.split("\r\n"):
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
        except Exception:
            pass
        return ""

    def _classify(self, ports: List[int], vendor: str, banner: str):
        port_set = set(ports)
        score = 0
        if 554 in port_set or 8554 in port_set: score += 3
        if 37777 in port_set or 34567 in port_set: score += 3
        if 8000 in port_set: score += 2
        if 1883 in port_set: score += 2

        vl = vendor.lower()
        bl = banner.lower()
        for v in CAM_VENDORS:
            if v in vl or v in bl:
                score += 5

        if 445 in port_set or 3389 in port_set:
            return "Windows", "workstation"
        if "mikrotik" in vl: return "RouterOS", "router"
        if "ubiquiti" in vl: return "UniFi OS", "router"

        if score >= 5:   return "Embedded Linux", "camera"
        if 37777 in port_set or 34567 in port_set: return "Embedded Linux", "nvr_dvr"
        if score >= 2:   return "Embedded Linux", "iot"
        return "Unknown", "unknown"

    def _get_local_subnet(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}"
        except Exception:
            return "192.168.1"
