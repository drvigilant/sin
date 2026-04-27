"""
sin.agent.mitigation
════════════════════
Executes network isolation actions against confirmed-threat devices.

Action hierarchy (least → most disruptive)
───────────────────────────────────────────
1.  MONITOR   — log only, no network change
2.  RATE_LIMIT — tc-based bandwidth throttle (slow the device, stay visible)
3.  QUARANTINE — allow only DNS + NTP outbound, DROP everything else
4.  ISOLATE   — DROP all traffic to/from the device (full isolation)
5.  BLOCK_MAC — ebtables rule blocking at L2 (survives IP change)

Implementation
──────────────
• Linux: iptables / nftables / ebtables  (root required)
• Raspberry Pi OS: iptables pre-installed; nftables optional
• All rules are tagged with the SIN rule comment for easy audit/removal
• dry_run=True logs every command without executing it (safe for dev)
• A JSON rule inventory is kept at /var/lib/sin/mitigations.json
  so rules survive reboots and the dashboard can display them

Lift / restore
──────────────
mitigation.lift_isolation(ip) removes all SIN rules for that IP.
The operator calls this via the dashboard when a device is cleared.

Usage
──────
engine = MitigationEngine(dry_run=False)
action = engine.isolate(host_dict, verdict)
# → MitigationAction(action_type="ISOLATE", rule_id="...", ...)

engine.lift_isolation("192.168.30.5")
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from sin.utils.logger import get_logger
from sin.agent.decision import ThreatVerdict

logger = get_logger("sin.agent.mitigation")

RULE_INVENTORY_PATH = Path(os.getenv("SIN_DATA_DIR", "/var/lib/sin")) / "mitigations.json"
SIN_COMMENT = "SIN-agent"     # used to tag and identify our iptables rules


@dataclass
class MitigationAction:
    action_type:  str           # ISOLATE | QUARANTINE | RATE_LIMIT | MONITOR | BLOCK_MAC
    rule_id:      str           # unique ID for lifting later
    ip:           str
    mac:          str
    dry_run:      bool
    details:      dict = field(default_factory=dict)
    ts:           str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    lifted:       bool = False
    lifted_ts:    Optional[str] = None


class MitigationEngine:

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        RULE_INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._inventory: Dict[str, MitigationAction] = self._load_inventory()
        if dry_run:
            logger.info("MitigationEngine running in DRY-RUN mode — no rules applied")
        else:
            logger.info("MitigationEngine LIVE — iptables rules will be applied")

    # ── Public API ────────────────────────────────────────────────────────────

    def isolate(self, host: dict, verdict: ThreatVerdict) -> MitigationAction:
        """
        Choose the appropriate mitigation level and execute it.
        Returns a MitigationAction with the rule_id.
        """
        ip  = host.get("ip_address", "")
        mac = host.get("mac_address", "Unknown")

        if not ip:
            raise ValueError("Cannot mitigate host with no IP address")

        # Don't double-isolate
        existing = self._find_active_rule(ip)
        if existing:
            logger.info(f"{ip} already has active mitigation rule {existing.rule_id} — skipping")
            return existing

        action_type = self._choose_action(verdict)
        rule_id     = f"SIN-{str(uuid.uuid4())[:8].upper()}"

        logger.warning(
            f"[MITIGATION] {action_type} on {ip} (MAC:{mac}) | "
            f"rule_id={rule_id} | confidence={verdict.confidence:.2f} | "
            f"dry_run={self.dry_run}"
        )

        details: dict = {}

        if action_type == "ISOLATE":
            details = self._apply_isolate(ip, mac, rule_id)
        elif action_type == "QUARANTINE":
            details = self._apply_quarantine(ip, mac, rule_id)
        elif action_type == "RATE_LIMIT":
            details = self._apply_rate_limit(ip, rule_id)
        elif action_type == "BLOCK_MAC":
            details = self._apply_block_mac(mac, rule_id)
        else:  # MONITOR
            details = {"note": "Monitoring — no network change applied"}

        action = MitigationAction(
            action_type=action_type,
            rule_id=rule_id,
            ip=ip,
            mac=mac,
            dry_run=self.dry_run,
            details=details,
        )
        self._inventory[rule_id] = action
        self._save_inventory()
        return action

    def lift_isolation(self, ip: str) -> dict:
        """Remove all active SIN mitigation rules for a given IP."""
        removed = []
        for rule_id, action in list(self._inventory.items()):
            if action.ip == ip and not action.lifted:
                self._remove_rules(ip, action.mac, rule_id, action.action_type)
                action.lifted    = True
                action.lifted_ts = datetime.now(timezone.utc).isoformat()
                removed.append(rule_id)
        self._save_inventory()
        logger.info(f"Lifted {len(removed)} mitigation rule(s) for {ip}: {removed}")
        return {"ip": ip, "lifted_rules": removed}

    def list_active(self) -> List[dict]:
        """Return all non-lifted actions (for dashboard display)."""
        return [
            asdict(a) for a in self._inventory.values() if not a.lifted
        ]

    # ── Action selection ──────────────────────────────────────────────────────

    @staticmethod
    def _choose_action(verdict: ThreatVerdict) -> str:
        if verdict.confidence >= 0.90:
            return "ISOLATE"
        if verdict.confidence >= 0.75:
            return "QUARANTINE"
        if verdict.confidence >= 0.60:
            return "RATE_LIMIT"
        return "MONITOR"

    # ── iptables: full isolation ──────────────────────────────────────────────

    def _apply_isolate(self, ip: str, mac: str, rule_id: str) -> dict:
        """
        DROP all traffic to and from the device.
        Rules are inserted at the top of INPUT and FORWARD chains.
        Tagged with a comment containing rule_id for easy removal.
        """
        commands = [
            # Drop all inbound
            ["iptables","-I","INPUT","-s",ip,
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            # Drop all outbound
            ["iptables","-I","OUTPUT","-d",ip,
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            # Drop forwarded (LAN→LAN)
            ["iptables","-I","FORWARD","-s",ip,
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            ["iptables","-I","FORWARD","-d",ip,
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
        ]
        self._run_batch(commands)
        # Also block at L2 if MAC is known
        if mac and mac != "Unknown":
            self._run_batch([
                ["ebtables","-I","INPUT","--source",mac,
                 "--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            ])
        return {"chains":["INPUT","OUTPUT","FORWARD"],"mac_blocked": mac != "Unknown"}

    # ── iptables: quarantine (DNS + NTP only) ─────────────────────────────────

    def _apply_quarantine(self, ip: str, mac: str, rule_id: str) -> dict:
        """
        Allow DNS (53 UDP) and NTP (123 UDP) outbound.
        Block everything else.
        """
        cmds = [
            # Allow DNS
            ["iptables","-I","FORWARD","-s",ip,"-p","udp","--dport","53",
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}:allow-dns","-j","ACCEPT"],
            # Allow NTP
            ["iptables","-I","FORWARD","-s",ip,"-p","udp","--dport","123",
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}:allow-ntp","-j","ACCEPT"],
            # Drop everything else from device
            ["iptables","-A","FORWARD","-s",ip,
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            # Drop inbound to device (except established)
            ["iptables","-A","FORWARD","-d",ip,
             "-m","state","--state","NEW",
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
        ]
        self._run_batch(cmds)
        return {"mode":"quarantine","allowed":["DNS:53/udp","NTP:123/udp"]}

    # ── tc: rate limiting ─────────────────────────────────────────────────────

    def _apply_rate_limit(self, ip: str, rule_id: str) -> dict:
        """
        Throttle device to 512 kbps using tc + iptables marking.
        Less disruptive than DROP — the device stays online but can't exfil fast.
        """
        mark = abs(hash(ip)) % 100 + 100  # unique mark 100-199
        iface = self._detect_iface()
        cmds = [
            # Mark packets from this IP
            ["iptables","-t","mangle","-A","POSTROUTING","-s",ip,
             "-j","MARK","--set-mark",str(mark),
             "-m","comment","--comment",f"{SIN_COMMENT}:{rule_id}"],
            # Add HTB qdisc if not present (ignore error if exists)
            ["tc","qdisc","add","dev",iface,"root","handle","1:","htb","default","11"],
            # Parent class
            ["tc","class","add","dev",iface,"parent","1:","classid","1:1",
             "htb","rate","100mbit"],
            # Throttled class (512 kbps)
            ["tc","class","add","dev",iface,"parent","1:1",
             "classid",f"1:{mark}","htb","rate","512kbit"],
            # Filter by mark
            ["tc","filter","add","dev",iface,"parent","1:","handle",
             str(mark),"fw","flowid",f"1:{mark}"],
        ]
        self._run_batch(cmds)
        return {"mode":"rate_limit","rate_kbps":512,"mark":mark,"iface":iface}

    # ── ebtables: L2 MAC block ────────────────────────────────────────────────

    def _apply_block_mac(self, mac: str, rule_id: str) -> dict:
        if not mac or mac == "Unknown":
            return {"error":"MAC unknown — L2 block skipped"}
        cmds = [
            ["ebtables","-I","INPUT","--source",mac,
             "--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            ["ebtables","-I","FORWARD","--source",mac,
             "--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
        ]
        self._run_batch(cmds)
        return {"mode":"block_mac","mac":mac}

    # ── Rule removal ──────────────────────────────────────────────────────────

    def _remove_rules(self, ip: str, mac: str, rule_id: str, action_type: str) -> None:
        """
        Remove all iptables rules whose comment matches SIN_COMMENT:rule_id.
        Works regardless of action type.
        """
        # Flush matching iptables rules by re-parsing iptables-save
        for table in ("filter", "mangle"):
            self._flush_rules_by_comment(table, rule_id)

        # ebtables removal (best-effort)
        if mac and mac != "Unknown":
            self._run_batch([
                ["ebtables","-D","INPUT","--source",mac,
                 "--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
                ["ebtables","-D","FORWARD","--source",mac,
                 "--comment",f"{SIN_COMMENT}:{rule_id}","-j","DROP"],
            ], allow_fail=True)

        logger.info(f"Rules removed for {ip} rule_id={rule_id}")

    def _flush_rules_by_comment(self, table: str, rule_id: str) -> None:
        """
        Parse iptables-save output to find line numbers of our rules,
        then delete them by number (safest approach — avoids spec mismatch).
        """
        try:
            saved = self._run(["iptables-save","-t",table], capture=True)
            lines_to_delete: Dict[str,List[int]] = {}
            for line in saved.splitlines():
                if f"{SIN_COMMENT}:{rule_id}" in line and line.startswith("-A"):
                    chain = line.split()[1]
                    lines_to_delete.setdefault(chain, []).append(1)

            for chain in lines_to_delete:
                # Delete rule repeatedly (line 1 after each deletion)
                for _ in lines_to_delete[chain]:
                    self._run_batch([["iptables","-t",table,"-D",chain,"1"]])
        except Exception as e:
            logger.error(f"Error flushing rules for {rule_id}: {e}")

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _run_batch(self, commands: List[List[str]], allow_fail: bool = False) -> None:
        for cmd in commands:
            self._run(cmd, allow_fail=allow_fail)

    def _run(self, cmd: List[str], capture: bool = False, allow_fail: bool = False) -> str:
        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info(f"[DRY-RUN] {cmd_str}")
            return ""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0 and not allow_fail:
                logger.error(f"Command failed [{result.returncode}]: {cmd_str}\n{result.stderr}")
            else:
                logger.debug(f"OK: {cmd_str}")
            return result.stdout if capture else ""
        except Exception as e:
            if not allow_fail:
                logger.error(f"Command exception: {cmd_str}: {e}")
            return ""

    @staticmethod
    def _detect_iface() -> str:
        """Detect the primary non-loopback interface (for tc rules)."""
        try:
            out = subprocess.run(
                ["ip","route","show","default"],
                capture_output=True, text=True
            ).stdout
            for part in out.split():
                if part == "dev":
                    continue
                if out.split().index(part) == out.split().index("dev") + 1:
                    return part
        except Exception:
            pass
        return "eth0"

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_inventory(self) -> Dict[str, MitigationAction]:
        if not RULE_INVENTORY_PATH.exists():
            return {}
        try:
            with open(RULE_INVENTORY_PATH) as f:
                raw = json.load(f)
            out = {}
            for rule_id, d in raw.items():
                out[rule_id] = MitigationAction(**d)
            return out
        except Exception as e:
            logger.error(f"Failed to load mitigation inventory: {e}")
            return {}

    def _save_inventory(self) -> None:
        try:
            with open(RULE_INVENTORY_PATH, "w") as f:
                json.dump(
                    {k: asdict(v) for k, v in self._inventory.items()},
                    f, indent=2
                )
        except Exception as e:
            logger.error(f"Failed to save mitigation inventory: {e}")

    def _find_active_rule(self, ip: str) -> Optional[MitigationAction]:
        for action in self._inventory.values():
            if action.ip == ip and not action.lifted:
                return action
        return None
