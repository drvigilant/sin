"""
sin.scanner.mac_resolver
═════════════════════════
Resolves MAC addresses for discovered IPs via two methods:

  1. /proc/net/arp  — instant, zero packets, works whenever the host
     has already communicated with the target (always true mid-scan).
     Requires host-network Docker or --cap-add NET_ADMIN.

  2. Scapy ARP request — sends a single layer-2 ARP who-has packet,
     waits up to 1 s for a reply.  Requires root or CAP_NET_RAW.
     Only used as fallback when /proc/net/arp misses.

The OUI lookup is fully offline — no external calls.
The top 50 IoT/camera vendor OUI prefixes are embedded so we can
identify vendor from MAC even when banner/ONVIF data is absent.
"""
from __future__ import annotations

import os
import re
import socket
from typing import Dict, Optional

from sin.utils.logger import get_logger

logger = get_logger("sin.scanner.mac_resolver")

# ── Offline OUI table (top IoT/CCTV/network vendors) ──────────────────────
# Format: "xx:xx:xx" (lowercase, colon-separated 3-octet prefix) → vendor
_OUI: Dict[str, str] = {
    # Hikvision
    "44:19:b6": "Hikvision", "bc:ad:28": "Hikvision",
    "c0:56:e3": "Hikvision", "4c:bd:8f": "Hikvision",
    "28:57:be": "Hikvision", "d0:c0:bf": "Hikvision",
    "a4:14:37": "Hikvision", "f4:a7:39": "Hikvision",
    # Dahua
    "e0:50:8b": "Dahua", "90:02:a9": "Dahua",
    "3c:ef:8c": "Dahua", "48:ea:63": "Dahua",
    "a4:6c:2a": "Dahua",
    # Axis
    "00:40:8c": "Axis",  "ac:cc:8e": "Axis",
    "00:30:4f": "Axis",
    # Reolink
    "ec:71:db": "Reolink",
    # Uniview / Zhejiang Uniview
    "d4:e8:80": "Uniview", "00:07:02": "Uniview",
    # Hanwha (Samsung Techwin)
    "00:09:18": "Hanwha",  "00:0d:f0": "Hanwha",
    # TP-Link / Tapo
    "50:d4:f7": "TP-Link", "ec:08:6b": "TP-Link",
    "00:1d:0f": "TP-Link", "98:de:d0": "TP-Link",
    # Ubiquiti
    "00:27:22": "Ubiquiti", "24:a4:3c": "Ubiquiti",
    "78:8a:20": "Ubiquiti", "f0:9f:c2": "Ubiquiti",
    # Cisco / Meraki
    "00:00:0c": "Cisco",  "00:50:56": "VMware/Cisco",
    "88:15:44": "Cisco Meraki",
    # Fortinet
    "00:09:0f": "Fortinet",
    # Mikrotik
    "4c:5e:0c": "Mikrotik", "d4:ca:6d": "Mikrotik",
    "74:4d:28": "Mikrotik",
    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    # Generic Chinese OEM / Xiongmai board
    "00:12:12": "Xiongmai-OEM",
}

_MAC_RE = re.compile(r"^([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})$")


def _read_proc_arp(ip: str) -> Optional[str]:
    """Read /proc/net/arp for a cached MAC — zero network activity."""
    try:
        with open("/proc/net/arp") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].lower()
                    if mac and mac != "00:00:00:00:00:00" and _MAC_RE.match(mac):
                        return mac
    except OSError:
        pass
    return None


def _scapy_arp(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Send a single ARP who-has and return the MAC from the reply."""
    try:
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _ = srp(pkt, timeout=timeout, verbose=False, retry=0)
        if answered:
            mac = answered[0][1].hwsrc.lower()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    except Exception as e:
        logger.debug(f"[mac_resolver] scapy ARP failed for {ip}: {e}")
    return None


def resolve_mac(ip: str) -> str:
    """
    Return the MAC address for *ip*, or "" if not resolvable.
    Tries /proc/net/arp first, then a live scapy ARP request.
    """
    # 1. Kernel ARP cache — fastest, no packets
    mac = _read_proc_arp(ip)
    if mac:
        logger.debug(f"[mac_resolver] {ip} → {mac} (proc/arp)")
        return mac

    # 2. Live ARP request
    mac = _scapy_arp(ip)
    if mac:
        logger.debug(f"[mac_resolver] {ip} → {mac} (scapy)")
        return mac

    logger.debug(f"[mac_resolver] {ip} → unresolved")
    return ""


def oui_vendor(mac: str) -> str:
    """
    Return vendor name from offline OUI table, or "" if unknown.
    Accepts any standard MAC notation.
    """
    if not mac:
        return ""
    normalised = mac.lower().replace("-", ":").replace(".", ":")
    # Ensure 3-octet prefix in colon form
    parts = [p for p in normalised.split(":") if p]
    if len(parts) < 3:
        return ""
    prefix = ":".join(parts[:3])
    return _OUI.get(prefix, "")


class MACResolver:
    """Stateless wrapper — instantiated once as a module-level singleton."""

    def resolve(self, ip: str) -> Dict[str, str]:
        """
        Returns {"mac_address": "...", "oui_vendor": "..."}.
        Both fields are "" when resolution fails.
        """
        mac = resolve_mac(ip)
        vendor = oui_vendor(mac) if mac else ""
        return {"mac_address": mac, "oui_vendor": vendor}


mac_resolver = MACResolver()
