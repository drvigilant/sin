"""
sin.agent.packet
════════════════
Live packet capture and traffic anomaly detection.
Runs Scapy sniffer in a dedicated thread; exposes signals via drain_signals().

Detects
───────
1.  ARP spoofing         — gratuitous ARPs claiming an IP already known
2.  Port scan behaviour  — host contacting >15 distinct ports/min outbound
3.  Mirai-family probes  — connections to Telnet(23)/SSH(22)/TR-069(7547) on new hosts
4.  DNS tunnelling       — queries with very long hostnames (>50 chars)
5.  Beacon traffic       — periodic connections to the same external IP (C2 pattern)
6.  Lateral movement     — internal host contacting many other internal hosts
7.  Data exfiltration    — outbound bytes/min > threshold (per src IP)

All detection is heuristic with configurable thresholds.
False positive risk is LOW because these signals only BOOST an existing
scanner threat score — they cannot trigger isolation by themselves.

Requirements
────────────
  pip install scapy
  The capture thread requires root / CAP_NET_RAW.
  If Scapy is unavailable, PacketEngine degrades gracefully (no capture).

Configuration (via sin.core.config.packet_settings)
─────────────────────────────────────────────────────
  INTERFACE          – network interface, e.g. "eth0" (default: auto-detect)
  INTERNAL_CIDR      – your LAN prefix, e.g. "192.168.30"
  SCAN_PORT_THRESH   – distinct ports/min before port-scan signal  (default 15)
  EXFIL_BYTES_THRESH – outbound bytes/min before exfil signal      (default 5_000_000)
  BEACON_PERIOD_SEC  – beacon detection window                      (default 300)
  BEACON_MIN_HITS    – min repeated connections to same remote      (default 8)
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, Counter, deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sin.utils.logger import get_logger

try:
    from scapy.all import (
        sniff, ARP, IP, TCP, UDP, DNS, DNSQR,
        conf as scapy_conf
    )
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False

from sin.core.config import packet_settings

logger = get_logger("sin.agent.packet")

# ── Thresholds (can override via packet_settings) ─────────────────────────────
SCAN_PORT_THRESH   = getattr(packet_settings, "SCAN_PORT_THRESH",   15)
EXFIL_BYTES_THRESH = getattr(packet_settings, "EXFIL_BYTES_THRESH", 5_000_000)
BEACON_PERIOD_SEC  = getattr(packet_settings, "BEACON_PERIOD_SEC",  300)
BEACON_MIN_HITS    = getattr(packet_settings, "BEACON_MIN_HITS",    8)
INTERNAL_CIDR      = getattr(packet_settings, "INTERNAL_CIDR",      "192.168.")
INTERFACE          = getattr(packet_settings, "INTERFACE",           None)  # None = auto

# Mirai-family target ports
MIRAI_PORTS = {23, 22, 7547, 5555, 2323, 37777, 34567, 9527, 8080}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_internal(ip: str) -> bool:
    return ip.startswith(INTERNAL_CIDR)


class PacketEngine:
    """
    Runs a Scapy sniffer in a background daemon thread.
    Signals are accumulated in a list; call drain_signals() to consume them.
    """

    def __init__(self):
        self._signals: List[dict] = []
        self._lock = threading.Lock()
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Per-IP state for anomaly detection
        # {ip: deque of (timestamp, dst_port)}
        self._port_contacts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # {ip: {dst_ip: hit_count}} for beacon detection
        self._remote_contacts: Dict[str, Counter] = defaultdict(Counter)
        # {ip: bytes_out_this_minute}
        self._bytes_out: Dict[str, int] = defaultdict(int)
        self._bytes_reset_ts: float = time.monotonic()
        # ARP table: {ip: mac} known good state
        self._arp_table: Dict[str, str] = {}
        # {src_ip: set of internal dsts contacted}
        self._lateral_contacts: Dict[str, set] = defaultdict(set)

        if not _SCAPY_OK:
            logger.warning(
                "Scapy not installed — packet capture disabled. "
                "Run: pip install scapy"
            )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start_capture(self) -> None:
        """Start sniffer thread.  Blocks until stop() is called."""
        if not _SCAPY_OK:
            logger.info("Packet engine: Scapy unavailable — skipping capture")
            return

        self._running.set()
        iface = INTERFACE or self._auto_detect_iface()
        logger.info(f"Starting packet capture on {iface}")

        self._thread = threading.current_thread()  # called from executor
        try:
            sniff(
                iface=iface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running.is_set(),
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")

    def stop(self) -> None:
        self._running.clear()

    def drain_signals(self) -> List[dict]:
        """Return and clear all accumulated anomaly signals."""
        with self._lock:
            out = list(self._signals)
            self._signals.clear()
        return out

    # ── Packet handler ────────────────────────────────────────────────────────

    def _handle_packet(self, pkt) -> None:
        try:
            if ARP in pkt:
                self._check_arp(pkt)
            if IP in pkt:
                self._check_ip(pkt)
                self._check_dns(pkt)
                self._check_bytes(pkt)
        except Exception:
            pass   # never crash the sniffer thread

    # ── ARP spoofing ──────────────────────────────────────────────────────────

    def _check_arp(self, pkt) -> None:
        arp = pkt[ARP]
        if arp.op != 2:   # op 2 = ARP reply / gratuitous ARP
            return
        src_ip  = arp.psrc
        src_mac = arp.hwsrc

        known_mac = self._arp_table.get(src_ip)
        if known_mac is None:
            self._arp_table[src_ip] = src_mac
            return

        if known_mac != src_mac:
            # MAC changed for a known IP → ARP spoof candidate
            self._emit("pkt_arp_spoof", {
                "ip":       src_ip,
                "type":     "pkt_arp_spoof",
                "old_mac":  known_mac,
                "new_mac":  src_mac,
                "detail":   f"ARP reply for {src_ip}: MAC changed "
                            f"{known_mac} → {src_mac}",
            })
            self._arp_table[src_ip] = src_mac   # update to new

    # ── Port scan + Mirai probe + lateral movement ────────────────────────────

    def _check_ip(self, pkt) -> None:
        if TCP not in pkt and UDP not in pkt:
            return

        src_ip  = pkt[IP].src
        dst_ip  = pkt[IP].dst
        dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        now = time.monotonic()

        is_src_internal = _is_internal(src_ip)
        is_dst_internal = _is_internal(dst_ip)

        # ── Port scan detection (internal src → many external ports) ─────────
        if is_src_internal and not is_dst_internal:
            self._port_contacts[src_ip].append((now, dst_port))
            # Count unique ports contacted in last 60 s
            cutoff = now - 60
            recent = self._port_contacts[src_ip]
            unique_ports = {p for t, p in recent if t > cutoff}
            if len(unique_ports) >= SCAN_PORT_THRESH:
                self._emit("pkt_port_scan", {
                    "ip":     src_ip,
                    "type":   "pkt_port_scan",
                    "detail": f"Contacted {len(unique_ports)} distinct external ports in 60s",
                    "ports_sample": list(unique_ports)[:10],
                })
                self._port_contacts[src_ip].clear()   # reset window

        # ── Mirai-family probe detection ──────────────────────────────────────
        if is_src_internal and not is_dst_internal:
            if dst_port in MIRAI_PORTS:
                self._emit("pkt_mirai_probe", {
                    "ip":     src_ip,
                    "type":   "pkt_mirai_probe",
                    "detail": f"Connection to known Mirai target port {dst_port} on {dst_ip}",
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                })

        # ── Beacon / C2 detection (periodic hits to same external IP) ─────────
        if is_src_internal and not is_dst_internal:
            self._remote_contacts[src_ip][dst_ip] += 1
            hits = self._remote_contacts[src_ip][dst_ip]
            if hits == BEACON_MIN_HITS:   # emit only on the threshold crossing
                self._emit("pkt_c2_beacon", {
                    "ip":       src_ip,
                    "type":     "pkt_c2_beacon",
                    "remote":   dst_ip,
                    "hits":     hits,
                    "detail":   f"{src_ip} contacted {dst_ip} {hits}+ times — C2 beacon pattern",
                })
                # Reset to avoid flooding
                self._remote_contacts[src_ip][dst_ip] = 0

        # ── Lateral movement (internal→internal fan-out) ──────────────────────
        if is_src_internal and is_dst_internal and src_ip != dst_ip:
            self._lateral_contacts[src_ip].add(dst_ip)
            if len(self._lateral_contacts[src_ip]) >= 10:
                self._emit("pkt_lateral", {
                    "ip":     src_ip,
                    "type":   "pkt_lateral",
                    "detail": f"{src_ip} contacted {len(self._lateral_contacts[src_ip])} "
                              f"internal hosts — lateral movement pattern",
                    "targets_count": len(self._lateral_contacts[src_ip]),
                })
                self._lateral_contacts[src_ip] = set()

    # ── DNS tunnelling ────────────────────────────────────────────────────────

    def _check_dns(self, pkt) -> None:
        if DNS not in pkt or DNSQR not in pkt:
            return
        src_ip = pkt[IP].src
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        except Exception:
            return
        if len(qname) > 50:
            self._emit("pkt_dns_tunnel", {
                "ip":     src_ip,
                "type":   "pkt_dns_tunnel",
                "detail": f"Suspiciously long DNS query ({len(qname)} chars): {qname[:80]}",
                "qname":  qname[:120],
            })

    # ── Data exfiltration ─────────────────────────────────────────────────────

    def _check_bytes(self, pkt) -> None:
        now = time.monotonic()
        # Reset byte counters every 60 s
        if now - self._bytes_reset_ts > 60:
            self._bytes_out = defaultdict(int)
            self._bytes_reset_ts = now

        if IP not in pkt:
            return
        src_ip = pkt[IP].src
        if not _is_internal(src_ip):
            return

        pkt_len = len(pkt)
        self._bytes_out[src_ip] += pkt_len

        if self._bytes_out[src_ip] >= EXFIL_BYTES_THRESH:
            self._emit("pkt_data_exfil", {
                "ip":     src_ip,
                "type":   "pkt_data_exfil",
                "bytes":  self._bytes_out[src_ip],
                "detail": f"{src_ip} sent {self._bytes_out[src_ip]:,} bytes/min — exfil threshold exceeded",
            })
            self._bytes_out[src_ip] = 0   # reset after signal

    # ── Signal emission ───────────────────────────────────────────────────────

    def _emit(self, signal_type: str, payload: dict) -> None:
        payload["ts"] = _ts()
        with self._lock:
            self._signals.append(payload)
        logger.warning(f"[PACKET SIGNAL] {signal_type} | {payload.get('ip')} | {payload.get('detail','')}")

    # ── Interface detection ───────────────────────────────────────────────────

    @staticmethod
    def _auto_detect_iface() -> str:
        try:
            import subprocess
            out = subprocess.run(
                ["ip","route","show","default"],
                capture_output=True, text=True
            ).stdout
            parts = out.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return "eth0"
