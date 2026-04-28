import uuid
from datetime import datetime
from typing import Dict
from sqlalchemy.orm import Session

from sin.agent.signal_mapper import normalize_host
from sin.core.risk_engine import calculate_risk
from sin.agent.decision import DecisionEngine
from sin.agent.mitigation import MitigationEngine
from sin.discovery.network import NetworkDiscovery
from sin.scanner.analyzer import StateAnalyzer
from sin.scanner.fingerprint import DeviceFingerprinter
from sin.scanner.audit import VulnerabilityAuditor
from sin.response.alert import DiscordAlerter
from sin.utils.logger import get_logger
from sin.storage.database import SessionLocal
from sin.storage import models

logger = get_logger("sin.agent.runner")

_IOT_HARD = {554, 8554, 37777, 34567, 8000, 9000, 1883, 8883, 5683, 47808, 502, 4840}
_PC_ONLY  = {445, 3389, 5985, 5986, 139, 135}
_NON_IOT_MFR = {
    "Apple", "Dell", "HP", "HPE", "Lenovo", "Microsoft",
    "ASUSTeK", "Acer", "Samsung Electronics", "Sony", "LG Electronics",
}
_NON_IOT_OS = ("windows", "ubuntu", "debian", "centos", "fedora", "macos")


def _is_iot(asset: Dict) -> bool:
    ports   = set(asset.get("open_ports", []))
    mfr     = asset.get("manufacturer", asset.get("vendor", ""))
    os_hint = asset.get("os_family", "").lower()
    if not ports:                               return False
    if mfr in _NON_IOT_MFR:                    return False
    if any(h in os_hint for h in _NON_IOT_OS): return False
    if _IOT_HARD.intersection(ports):           return True
    if ports.issubset(_PC_ONLY):               return False
    if ports.issubset({80, 443, 22, 8080}):    return False
    return True


class AgentRunner:
    def __init__(self):
        self.discovery_module   = NetworkDiscovery()
        self.fingerprint_module = DeviceFingerprinter()
        self.audit_module       = VulnerabilityAuditor()
        self.alerter            = DiscordAlerter()
        self.session_uuid       = str(uuid.uuid4())
        self.decision           = DecisionEngine()
        self.mitigation         = MitigationEngine(dry_run=True)

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        logger.info(f"Starting assessment session: {self.session_uuid}")
        start_time = datetime.utcnow()

        raw_assets = self.discovery_module.execute_subnet_scan(subnet)
        logger.info(f"Discovery complete. Total assets found: {len(raw_assets)}")

        iot_assets = []
        for asset in raw_assets:
            analysis = self.fingerprint_module.analyze_asset(
                asset["ip_address"],
                asset.get("open_ports", []),
            )
            asset.update(analysis)

            if _is_iot(asset):
                iot_assets.append(asset)
            else:
                logger.info(
                    f"Dropped Non-IoT: {asset['ip_address']} "
                    f"| Ports: {asset.get('open_ports',[])} "
                    f"| Vendor: {asset.get('vendor','?')}"
                )

        logger.info(f"IoT assets after filter: {len(iot_assets)} / {len(raw_assets)}")

        enriched_assets = []
        for asset in iot_assets:
            vulns = self.audit_module.audit_device(
                ip_address=asset["ip_address"],
                open_ports=asset.get("open_ports", []),
                vendor=asset.get("vendor") or asset.get("manufacturer", ""),
                os_family=asset.get("os_family", ""),
            )
            asset["vulnerabilities"] = vulns

            risk = calculate_risk(asset)
            asset["risk_score"] = risk["risk_score"]
            asset["risk_level"] = risk["risk_level"]

            normalized_asset = normalize_host(asset)
            verdict = self.decision.evaluate(normalized_asset)

            asset["decision"] = {
                "score":          verdict.score,
                "confidence":     verdict.confidence,
                "severity":       verdict.severity,
                "action":         verdict.recommended_action,
                "reasons":        verdict.reasons,
                "signal_count":   verdict.signal_count,
                "packet_signals": verdict.packet_signals_count,
            }

            logger.info(
                f"[DECISION] {asset['ip_address']} | "
                f"risk={asset['risk_score']} ({asset['risk_level']}) | "
                f"action={verdict.recommended_action} | "
                f"confidence={verdict.confidence:.2f}"
            )

            if verdict.recommended_action == "isolate" and verdict.confidence >= 0.80:
                logger.warning(
                    f"AUTO-ISOLATING {asset['ip_address']} | "
                    f"confidence={verdict.confidence:.2f}"
                )
                self.mitigation.isolate(asset, verdict)

            if vulns:
                logger.warning(f"Vulnerabilities found on {asset['ip_address']}")

            enriched_assets.append(asset)

        end_time = datetime.utcnow()
        self._save_to_database(subnet, start_time, end_time, enriched_assets)

    def _save_to_database(self, subnet, start, end, assets):
        db: Session = SessionLocal()
        analyzer = StateAnalyzer(db)
        try:
            scan_session = models.ScanSession(
                session_uuid=self.session_uuid,
                subnet_target=subnet,
                start_time=start,
                end_time=end,
            )
            db.add(scan_session)
            db.commit()
            db.refresh(scan_session)

            for asset in assets:
                changes = analyzer.analyze_changes(asset)

                dangerous_ports = {21: "FTP", 23: "Telnet"}
                for port in asset.get("open_ports", []):
                    if port in dangerous_ports:
                        changes.append({
                            "type": "HEURISTIC_FLAG",
                            "severity": "CRITICAL",
                            "description": (
                                f"Insecure protocol: {dangerous_ports[port]} "
                                f"(Port {port}) on {asset['ip_address']}."
                            ),
                        })

                critical_changes = []
                for change in changes:
                    db.add(models.SecurityEvent(
                        ip_address=asset["ip_address"],
                        event_type=change["type"],
                        severity=change["severity"],
                        description=change["description"],
                    ))
                    if change["severity"] in ("WARNING", "CRITICAL"):
                        critical_changes.append(change)

                if critical_changes:
                    logger.warning(f"Security events triggered on {asset['ip_address']}")
                    self.alerter.send_critical_alert(asset["ip_address"], critical_changes)

                enrichment_meta = list(set(asset.get("protocol_hints", []))) + [
                    f"MAC:{asset.get('mac_address', 'Unknown')}",
                    f"HOST:{asset.get('hostname', 'Unknown')}",
                    f"MFR:{asset.get('manufacturer', asset.get('vendor', 'Unknown'))}",
                ]

                db.add(models.DeviceLog(
                    scan_id=scan_session.id,
                    ip_address=asset["ip_address"],
                    status=asset["status"],
                    open_ports=asset.get("open_ports", []),
                    protocols=enrichment_meta,
                    os_family=asset.get("os_family"),
                    vendor=asset.get("vendor") or asset.get("manufacturer"),
                    vulnerabilities=asset.get("vulnerabilities", []),
                ))

            db.commit()
            logger.info(f"Saved {len(assets)} IoT devices to database.")

        except Exception as e:
            logger.error(f"Database save failed: {e}")
            db.rollback()
        finally:
            db.close()

    def _persist_json(self, data: Dict, directory: str) -> None:
        pass
