import socket
from typing import Dict, List, Tuple
from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.fingerprint")

class DeviceFingerprinter:
    """
    Analyzes network assets to determine OS, Vendor, and Device Type.
    """
    
    def __init__(self):
        self.signature_db = {
            21: "FTP",
            22: "SSH/Linux",
            23: "Telnet/IoT",
            80: "HTTP/Web",
            443: "HTTPS/Web",
            445: "SMB/Windows",
            554: "RTSP/Camera",
            1883: "MQTT/SmartHome",
            3389: "RDP/Windows",
            8080: "HTTP-Proxy"
        }

    def analyze_asset(self, ip: str, open_ports: List[int]) -> Dict:
        """
        Main entry point for fingerprinting a device.
        """
        # 1. Default Guesses
        os_guess = "Unknown"
        vendor_guess = "Generic"
        
        # 2. Port-Based Logic (The "Heuristic" Phase)
        if 445 in open_ports or 3389 in open_ports:
            os_guess = "Windows"
            vendor_guess = "Microsoft"
        elif 22 in open_ports:
            # 3. Banner Grabbing (The "Active" Phase)
            banner = self._grab_banner(ip, 22)
            if "Ubuntu" in banner:
                os_guess = "Ubuntu Linux"
                vendor_guess = "Canonical"
            elif "Raspbian" in banner:
                os_guess = "Raspberry Pi OS"
                vendor_guess = "Raspberry Pi"
            else:
                os_guess = "Linux"
        
        if 554 in open_ports:
            vendor_guess = "Potential Camera/NVR"
            os_guess = "Embedded Linux"

        return {
            "os_family": os_guess,
            "vendor": vendor_guess,
            "raw_banner": self._grab_banner(ip, open_ports[0]) if open_ports else None
        }

    def _grab_banner(self, ip: str, port: int, timeout: float = 1.0) -> str:
        """
        Connects to a port and reads the first line of text (the banner).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                # Send a gentle byte to provoke a response (useful for some HTTP servers)
                if port in [80, 8080]:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except:
            return ""
