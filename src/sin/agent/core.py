"""
sin.agent.core
══════════════
The autonomous SIN agent.  Runs as a persistent asyncio loop.
On Raspberry Pi: launched via systemd (sin-agent.service).
On dev:          python -m sin.agent.core

Responsibilities
────────────────
1.  Periodic subnet scans (configurable interval, default 5 min)
2.  Continuous packet capture (Scapy sniffer in separate thread)
3.  Anomaly detection on captured traffic
4.  Decision engine evaluation for every discovered host
5.  Automated mitigation when confidence ≥ threshold
6.  Real-time event push to FastAPI WebSocket layer
7.  Audit log of every action taken

Wiring
──────
agent/core.py       ← you are here (orchestrator)
agent/decision.py   ← confidence scoring + false-positive guard
agent/mitigation.py ← iptables / VLAN isolation actions
agent/packet.py     ← Scapy capture + anomaly signals
agent/notify.py     ← Telegram / webhook alerts
discovery/network.py ← existing scanner (unchanged)
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from sin.utils.logger import get_logger
from sin.core.config import scanner_settings, agent_settings
from sin.discovery.network import NetworkDiscovery
from sin.agent.decision import DecisionEngine, ThreatVerdict
from sin.agent.mitigation import MitigationEngine
from sin.agent.packet import PacketEngine
from sin.agent.notify import NotificationRouter
from sin.storage.registry import DeviceRegistry   # SQLite asset store (see note below)

logger = get_logger("sin.agent.core")

# ── Event types ───────────────────────────────────────────────────────────────
class EventKind:
    SCAN_START      = "scan_start"
    SCAN_COMPLETE   = "scan_complete"
    DEVICE_NEW      = "device_new"
    DEVICE_UPDATED  = "device_updated"
    DEVICE_GONE     = "device_gone"
    THREAT_DETECTED = "threat_detected"
    ACTION_TAKEN    = "action_taken"
    PACKET_ANOMALY  = "packet_anomaly"
    HEARTBEAT       = "heartbeat"


class AgentEvent:
    __slots__ = ("kind","payload","ts","event_id")

    def __init__(self, kind: str, payload: dict):
        self.kind     = kind
        self.payload  = payload
        self.ts       = datetime.now(timezone.utc).isoformat()
        self.event_id = str(uuid.uuid4())[:8].upper()

    def to_dict(self) -> dict:
        return {"event_id":self.event_id,"kind":self.kind,
                "ts":self.ts,"payload":self.payload}


# ── Main agent ────────────────────────────────────────────────────────────────
class SINAgent:
    """
    Single instance per deployment.  Instantiate once and call run().

    Configuration (via sin.core.config.agent_settings):
        SCAN_INTERVAL_SEC   – seconds between full subnet scans  (default 300)
        SUBNETS             – list of CIDR prefixes, e.g. ["192.168.1","192.168.30"]
        AUTO_MITIGATE       – bool, whether to act without operator approval
        CONFIDENCE_THRESHOLD– float 0.0-1.0, minimum score to trigger action
        DRY_RUN             – bool, log actions but do NOT execute them
    """

    def __init__(self):
        self.discovery   = NetworkDiscovery()
        self.decision    = DecisionEngine()
        self.mitigation  = MitigationEngine(dry_run=agent_settings.DRY_RUN)
        self.packet_eng  = PacketEngine()
        self.notify      = NotificationRouter()
        self.registry    = DeviceRegistry()

        self._event_queue: asyncio.Queue = asyncio.Queue(maxsize=2048)
        self._ws_listeners: List[asyncio.Queue] = []   # FastAPI pushes subscribe here
        self._running  = False
        self._scan_lock = asyncio.Lock()

        # Anomaly signals from packet engine accumulate here.
        # {ip: [anomaly_dict, ...]}
        self._packet_signals: Dict[str, List[dict]] = defaultdict(list)

        logger.info(
            f"SIN Agent initialised | subnets={agent_settings.SUBNETS} | "
            f"interval={agent_settings.SCAN_INTERVAL_SEC}s | "
            f"auto_mitigate={agent_settings.AUTO_MITIGATE} | "
            f"dry_run={agent_settings.DRY_RUN}"
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def run(self) -> None:
        """Start all agent tasks.  Runs until SIGTERM/SIGINT."""
        self._running = True
        self._setup_signal_handlers()

        logger.info("SIN Agent starting up")

        tasks = [
            asyncio.create_task(self._scan_loop(),      name="scan-loop"),
            asyncio.create_task(self._event_loop(),     name="event-dispatch"),
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._packet_loop(),    name="packet-capture"),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Agent tasks cancelled — shutting down")
        finally:
            await self._shutdown()

    async def _shutdown(self) -> None:
        self._running = False
        self.packet_eng.stop()
        logger.info("SIN Agent shut down cleanly")

    def _setup_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._request_stop)

    def _request_stop(self) -> None:
        logger.info("Shutdown signal received")
        self._running = False
        for task in asyncio.all_tasks():
            task.cancel()

    # ── Scan loop ─────────────────────────────────────────────────────────────

    async def _scan_loop(self) -> None:
        """
        Runs a full subnet scan on every configured subnet, then sleeps.
        First scan fires immediately; subsequent ones after SCAN_INTERVAL_SEC.
        """
        first_run = True
        while self._running:
            if not first_run:
                await asyncio.sleep(agent_settings.SCAN_INTERVAL_SEC)
            first_run = False

            if self._scan_lock.locked():
                logger.warning("Previous scan still running — skipping cycle")
                continue

            async with self._scan_lock:
                for subnet in agent_settings.SUBNETS:
                    await self._scan_subnet(subnet)

    async def _scan_subnet(self, subnet: str) -> None:
        session_id = str(uuid.uuid4())[:8].upper()
        await self._emit(EventKind.SCAN_START, {"subnet": subnet, "session_id": session_id})
        logger.info(f"[{session_id}] Scanning {subnet}.0/24")

        loop = asyncio.get_event_loop()
        try:
            # Run blocking nmap scan in executor so the event loop stays free
            results: List[dict] = await loop.run_in_executor(
                None,
                self.discovery.execute_subnet_scan,
                subnet,
            )
        except Exception as e:
            logger.error(f"Scan failed for {subnet}: {e}")
            return

        logger.info(f"[{session_id}] {len(results)} hosts found in {subnet}")

        # Detect devices that have disappeared since last scan
        await self._check_gone_devices(subnet, results)

        for host in results:
            await self._process_host(host, session_id)

        await self._emit(EventKind.SCAN_COMPLETE, {
            "subnet": subnet,
            "session_id": session_id,
            "host_count": len(results),
        })

    async def _process_host(self, host: dict, session_id: str) -> None:
        ip = host["ip_address"]

        # Merge packet anomaly signals into host dict before decision
        host["_packet_signals"] = self._packet_signals.get(ip, [])

        # Registry: is this a new or updated device?
        is_new = not self.registry.exists(ip)
        self.registry.upsert(host)

        kind = EventKind.DEVICE_NEW if is_new else EventKind.DEVICE_UPDATED
        await self._emit(kind, {"ip": ip, "session_id": session_id,
                                "hostname": host.get("hostname"),
                                "manufacturer": host.get("manufacturer")})

        # ── Decision engine ────────────────────────────────────────────────
        verdict: ThreatVerdict = self.decision.evaluate(host)

        if verdict.score < 0.01:
            return   # clean device — nothing to do

        logger.warning(
            f"Threat signal on {ip} | score={verdict.score:.2f} | "
            f"confidence={verdict.confidence:.2f} | "
            f"reasons={verdict.reasons}"
        )

        await self._emit(EventKind.THREAT_DETECTED, {
            "ip": ip,
            "hostname": host.get("hostname"),
            "manufacturer": host.get("manufacturer"),
            "score": verdict.score,
            "confidence": verdict.confidence,
            "severity": verdict.severity,
            "reasons": verdict.reasons,
            "vulnerabilities": host.get("vulnerabilities", []),
        })

        # ── Notification (always) ──────────────────────────────────────────
        await asyncio.get_event_loop().run_in_executor(
            None, self.notify.send_threat, verdict, host
        )

        # ── Auto-mitigation guard ──────────────────────────────────────────
        if not agent_settings.AUTO_MITIGATE:
            logger.info(f"Auto-mitigate OFF — action not taken for {ip}")
            return

        if verdict.confidence < agent_settings.CONFIDENCE_THRESHOLD:
            logger.info(
                f"Confidence {verdict.confidence:.2f} < threshold "
                f"{agent_settings.CONFIDENCE_THRESHOLD} for {ip} — "
                f"alert only, no isolation"
            )
            return

        # ── Device is whitelisted? ─────────────────────────────────────────
        if self.registry.is_whitelisted(ip):
            logger.info(f"{ip} is whitelisted — skipping mitigation")
            return

        # ── Execute mitigation ─────────────────────────────────────────────
        action = await asyncio.get_event_loop().run_in_executor(
            None, self.mitigation.isolate, host, verdict
        )

        logger.warning(f"Mitigation executed on {ip}: {action}")
        await self._emit(EventKind.ACTION_TAKEN, {
            "ip": ip,
            "action": action.action_type,
            "rule_id": action.rule_id,
            "dry_run": action.dry_run,
            "details": action.details,
        })

    async def _check_gone_devices(self, subnet: str, current_results: List[dict]) -> None:
        """Emit DEVICE_GONE for IPs that were online last scan but not found now."""
        current_ips = {h["ip_address"] for h in current_results}
        previous = self.registry.get_all_in_subnet(subnet)
        for prev_ip in previous:
            if prev_ip not in current_ips:
                self.registry.mark_offline(prev_ip)
                await self._emit(EventKind.DEVICE_GONE, {"ip": prev_ip})
                logger.info(f"Device gone: {prev_ip}")

    # ── Packet capture loop ───────────────────────────────────────────────────

    async def _packet_loop(self) -> None:
        """
        Packet engine runs in a background thread.
        This coroutine polls its signal queue and routes anomalies.
        """
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.packet_eng.start_capture)

        while self._running:
            try:
                signals = self.packet_eng.drain_signals()
                for sig in signals:
                    ip = sig.get("ip")
                    if ip:
                        self._packet_signals[ip].append(sig)
                        # Keep only last 50 signals per IP
                        self._packet_signals[ip] = self._packet_signals[ip][-50:]
                    await self._emit(EventKind.PACKET_ANOMALY, sig)
            except Exception as e:
                logger.error(f"Packet loop error: {e}")
            await asyncio.sleep(2)

    # ── Event dispatch ────────────────────────────────────────────────────────

    async def _event_loop(self) -> None:
        """Drain the event queue and push to all WebSocket subscribers."""
        while self._running:
            try:
                event: AgentEvent = await asyncio.wait_for(
                    self._event_queue.get(), timeout=5.0
                )
                payload = event.to_dict()
                self.registry.log_event(payload)

                # Push to all connected WebSocket clients
                dead = []
                for q in self._ws_listeners:
                    try:
                        q.put_nowait(payload)
                    except asyncio.QueueFull:
                        dead.append(q)
                for d in dead:
                    self._ws_listeners.remove(d)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Event loop error: {e}")

    async def _heartbeat_loop(self) -> None:
        while self._running:
            await self._emit(EventKind.HEARTBEAT, {
                "uptime_s": int(time.monotonic()),
                "subnets": agent_settings.SUBNETS,
                "auto_mitigate": agent_settings.AUTO_MITIGATE,
            })
            await asyncio.sleep(30)

    async def _emit(self, kind: str, payload: dict) -> None:
        event = AgentEvent(kind, payload)
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Event queue full — dropping event")

    # ── WebSocket subscription API (called by FastAPI) ────────────────────────

    def subscribe(self) -> asyncio.Queue:
        """
        Returns a queue that receives every agent event as a JSON-serialisable dict.
        Call from FastAPI WebSocket handler:
            q = agent.subscribe()
            while True:
                data = await q.get()
                await ws.send_json(data)
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._ws_listeners.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._ws_listeners.remove(q)
        except ValueError:
            pass

    # ── Operator API (called by FastAPI endpoints) ────────────────────────────

    def whitelist_device(self, ip: str) -> None:
        self.registry.whitelist(ip)
        logger.info(f"Device whitelisted by operator: {ip}")

    def lift_isolation(self, ip: str) -> dict:
        """Remove iptables DROP rules for a previously isolated device."""
        result = self.mitigation.lift_isolation(ip)
        self.registry.mark_mitigated(ip, lifted=True)
        return result

    def trigger_scan(self, subnet: Optional[str] = None) -> str:
        """Queue an immediate scan.  Returns session_id."""
        session_id = str(uuid.uuid4())[:8].upper()
        targets = [subnet] if subnet else agent_settings.SUBNETS
        for s in targets:
            asyncio.create_task(self._scan_subnet(s))
        return session_id


# ── Entrypoint ────────────────────────────────────────────────────────────────
def main() -> None:
    import uvloop  # pip install uvloop  (faster event loop, optional but recommended)
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        logger.info("Using uvloop")
    except ImportError:
        logger.info("uvloop not found — using default asyncio loop")

    agent = SINAgent()
    asyncio.run(agent.run())


if __name__ == "__main__":
    main()
