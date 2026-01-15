import socket
import concurrent.futures
import subprocess
import platform
from typing import List, Dict, Optional
from sin.utils.logger import get_logger
from sin.core.config import scanner_settings

logger = get_logger("sin.discovery.network")

class NetworkDiscovery:
    """
    Handles network reconnaissance and asset discovery operations.
    """
    
    def __init__(self):
        self.threads = scanner_settings.DEFAULT_THREADS
        self.timeout = scanner_settings.TIMEOUT

    def _check_host_availability(self, ip: str) -> bool:
        """
        Verifies if a host is reachable via ICMP echo.
        """
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        cmd = ['ping', param, '1', ip]
        
        try:
            return subprocess.call(
                cmd, 
                stdout=subprocess.DEVNULL, 
                stderr=subprocess.DEVNULL
            ) == 0
        except Exception as e:
            logger.error(f"ICMP check failed for {ip}: {e}")
            return False

    def _scan_port_services(self, ip: str) -> List[int]:
        """
        Identifies open ports on the target host.
        """
        open_ports = []
        for port in scanner_settings.COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
            except socket.error:
                continue
        return open_ports

    def scan_target(self, ip: str) -> Optional[Dict]:
        """
        Performs comprehensive discovery on a single target IP.
        """
        if self._check_host_availability(ip):
            ports = self._scan_port_services(ip)
            return {
                "ip_address": ip,
                "status": "online",
                "open_ports": ports,
                "protocol_hints": self._identify_protocols(ports)
            }
        return None

    def _identify_protocols(self, ports: List[int]) -> List[str]:
        """Maps ports to likely service protocols."""
        service_map = {
            22: "SSH", 80: "HTTP", 443: "HTTPS", 
            1883: "MQTT", 502: "MODBUS"
        }
        return [service_map.get(p, "UNKNOWN") for p in ports]

    def execute_subnet_scan(self, subnet_cidr: str) -> List[Dict]:
        """
        Orchestrates a multi-threaded scan across a subnet.
        Input format expected: '192.168.1' (Implies /24)
        """
        logger.info(f"Initiating discovery sequence on subnet: {subnet_cidr}.0/24")
        
        targets = [f"{subnet_cidr}.{i}" for i in range(1, 255)]
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.scan_target, ip): ip for ip in targets}
            
            for future in concurrent.futures.as_completed(future_to_ip):
                try:
                    data = future.result()
                    if data:
                        logger.info(f"Asset discovered: {data['ip_address']}")
                        results.append(data)
                except Exception as e:
                    logger.error(f"Scan error on target: {e}")
        
        logger.info(f"Discovery complete. Total assets found: {len(results)}")
        return results
