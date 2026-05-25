"""
sin.agent.mitigation
════════════════════
Executes isolation actions against high-risk devices.
Now upgraded with Active ARP Quarantine to isolate devices
even if SIN is not the network's default gateway.
"""
import subprocess
import threading
import time
import re
from typing import Dict, Any

from sin.utils.logger import get_logger
from sin.agent.decision import ThreatVerdict

# Import Scapy for Active ARP Quarantine
try:
    from scapy.all import ARP, Ether, sendp, getmacbyip, conf
except ImportError:
    ARP = Ether = sendp = getmacbyip = conf = None

logger = get_logger("sin.agent.mitigation")

class MitigationAction:
    def __init__(self, action_type: str, rule_id: str, dry_run: bool, details: Dict[str, Any]):
        self.action_type = action_type
        self.rule_id = rule_id
        self.dry_run = dry_run
        self.details = details

    def __str__(self):
        prefix = "[DRY-RUN] " if self.dry_run else ""
        return f"{prefix}{self.action_type} executed (rule: {self.rule_id})"


class MitigationEngine:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._active_quarantines = {}  # Tracks running ARP poison threads {ip: stop_event}

        if not ARP:
            logger.warning("Scapy is not installed. ARP Quarantine will be disabled. Run: pip install scapy")

    def isolate(self, host: dict, verdict: ThreatVerdict) -> MitigationAction:
        """
        Determines the best isolation strategy based on the threat and executes it.
        """
        ip = host.get("ip_address")
        mac = host.get("mac_address", "unknown").lower()

        if not ip:
            return MitigationAction("failed", "none", self.dry_run, {"error": "No IP provided"})

        # Active ARP Quarantine (Market Leader feature)
        # We actively sever the device from the network instead of just dropping packets locally.
        if ARP:
            if mac == "unknown":
                # Dynamically resolve MAC if the Go sensor missed it
                resolved = getmacbyip(ip)
                mac = resolved if resolved else "ff:ff:ff:ff:ff:ff"

            details = self._apply_arp_quarantine(ip, mac)
            return MitigationAction("arp_quarantine", f"arp_drop_{ip}", self.dry_run, details)

        # Fallback to local iptables drop
        details = self._apply_iptables_drop(ip, mac)
        return MitigationAction("iptables_drop", f"fw_drop_{ip}", self.dry_run, details)

    def lift_isolation(self, ip: str) -> dict:
        """Reverses both iptables and active ARP quarantines."""
        results = {"ip": ip, "actions_reversed": []}

        # 1. Stop active ARP quarantine if running
        if ip in self._active_quarantines:
            stop_event = self._active_quarantines[ip]
            stop_event.set()  # Signals the thread to stop
            del self._active_quarantines[ip]
            results["actions_reversed"].append("arp_quarantine_stopped")
            logger.info(f"Halted ARP Quarantine for {ip}")

        # 2. Remove iptables rules
        if not self.dry_run:
            try:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, check=False)
                subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
                               capture_output=True, check=False)
                results["actions_reversed"].append("iptables_rules_removed")
            except Exception as e:
                logger.error(f"Failed to lift iptables for {ip}: {e}")

        return results

    # ── Internal Enforcement Methods ──────────────────────────────────────────

    def _apply_iptables_drop(self, ip: str, mac: str) -> dict:
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute iptables DROP for {ip}")
            return {"target": ip, "method": "iptables", "status": "simulated"}

        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
            return {"target": ip, "method": "iptables", "status": "enforced"}
        except Exception as e:
            logger.error(f"iptables enforcement failed for {ip}: {e}")
            return {"target": ip, "method": "iptables", "status": "failed", "error": str(e)}

    def _detect_gateway(self, target_ip: str) -> str:
        """
        Detect the actual gateway for target_ip by reading the kernel routing table.
        Falls back to subnet .1 with a warning if detection fails.
        """
        import os
        override = os.environ.get("SIN_GATEWAY_IP")
        if override:
            logger.info(f"Using SIN_GATEWAY_IP override: {override}")
            return override
        try:
            out = subprocess.check_output(
                ["ip", "route", "get", target_ip],
                text=True, timeout=3
            )
            m = re.search(r"via ([\d.]+)", out)
            if m:
                logger.debug(f"Detected gateway {m.group(1)} for {target_ip}")
                return m.group(1)
        except Exception as e:
            logger.warning(f"Gateway detection failed for {target_ip}: {e}")
        # Fallback
        gw = ".".join(target_ip.split(".")[:3]) + ".1"
        logger.warning(f"Using fallback gateway {gw} for {target_ip} — verify this is correct")
        return gw

    def _apply_arp_quarantine(self, target_ip: str, target_mac: str) -> dict:
        """
        Actively isolates the target by continuously telling it that the Gateway's IP
        belongs to a non-existent MAC address (blackholing its traffic).
        """
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would start ARP Quarantine thread for {target_ip}")
            return {"target": target_ip, "method": "arp_quarantine", "status": "simulated"}

        gateway_ip = self._detect_gateway(target_ip)
        fake_mac = "00:00:00:00:00:00"  # The Blackhole MAC

        if target_ip in self._active_quarantines:
            return {"target": target_ip, "status": "already_quarantined"}


        # Resolve gateway MAC BEFORE thread starts
        # Try kernel ARP table first (faster, no Scapy ARP broadcast needed)
        gateway_mac = None
        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if parts[0] == gateway_ip and parts[2] != '00:00:00:00:00:00':
                        gateway_mac = parts[3]
                        break
        except Exception:
            pass
        if not gateway_mac:
            gateway_mac = getmacbyip(gateway_ip) if getmacbyip else None
        if not gateway_mac:
            logger.error(f'Cannot resolve gateway MAC for {gateway_ip} — aborting quarantine')
            return {'target': target_ip, 'method': 'arp_quarantine', 'status': 'failed', 'error': 'gateway MAC unresolvable'}
        logger.info(f'Gateway {gateway_ip} MAC resolved: {gateway_mac}')

        # Create a thread event to stop the poisoning when 'lift_isolation' is called
        stop_event = threading.Event()
        self._active_quarantines[target_ip] = stop_event

        def arp_poison_loop():
            logger.warning(f"🚨 ARP Quarantine Initiated: Blackholing {target_ip} from Gateway {gateway_ip}")
            # Direction 1: Tell TARGET that gateway MAC = blackhole
            pkt_to_target = Ether(dst=target_mac) / ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwsrc=fake_mac)
            # Direction 2: Tell GATEWAY that target MAC = blackhole
            pkt_to_gateway = Ether(dst=gateway_mac) / ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwsrc=fake_mac)

            while not stop_event.is_set():
                try:
                    sendp(pkt_to_target, iface=conf.iface, verbose=False)
                    sendp(pkt_to_gateway, iface=conf.iface, verbose=False)
                except Exception as e:
                    logger.error(f"ARP poison failed for {target_ip}: {e}")
                stop_event.wait(2.0)

            logger.info(f"ARP Quarantine Thread terminated for {target_ip}")

        # Start the background enforcement thread
        t = threading.Thread(target=arp_poison_loop, daemon=True, name=f"Quarantine-{target_ip}")
        t.start()

        return {"target": target_ip, "method": "arp_quarantine", "status": "enforced", "gateway_spoofed": gateway_ip}
