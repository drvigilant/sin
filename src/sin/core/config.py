import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class SystemConfig:
    APP_NAME:  str = "SIN"
    VERSION:   str = "1.0.0"
    ENV:       str = os.getenv("SIN_ENV", "development")
    LOG_LEVEL: str = os.getenv("SIN_LOG_LEVEL", "INFO")


@dataclass
class ScannerConfig:
    DEFAULT_THREADS: int   = 50
    TIMEOUT:         float = 1.0
    COMMON_PORTS:    List[int] = field(default_factory=lambda: [
        80, 443, 554, 8080, 8443, 8554,
        37777, 34567, 8000, 9000,
        1883, 8883, 5683,
        21, 22, 23,
        161, 502, 47808,
    ])


@dataclass
class AgentConfig:
    SUBNETS:              List[str] = field(default_factory=lambda:
        os.getenv("SUBNETS", "192.168.1,192.168.30").split(","))
    SCAN_INTERVAL_SEC:    int   = int(os.getenv("SCAN_INTERVAL_SEC", "300"))
    AUTO_MITIGATE:        bool  = os.getenv("AUTO_MITIGATE", "false").lower() == "true"
    CONFIDENCE_THRESHOLD: float = float(os.getenv("CONFIDENCE_THRESHOLD", "0.80"))
    DRY_RUN:              bool  = os.getenv("DRY_RUN", "true").lower() == "true"
    DATA_DIR:             str   = os.getenv("SIN_DATA_DIR", "/var/lib/sin")


@dataclass
class PacketConfig:
    INTERFACE:          str   = os.getenv("INTERFACE", "eth0")
    INTERNAL_CIDR:      str   = os.getenv("INTERNAL_CIDR", "192.168.")
    SCAN_PORT_THRESH:   int   = int(os.getenv("SCAN_PORT_THRESH", "15"))
    EXFIL_BYTES_THRESH: int   = int(os.getenv("EXFIL_BYTES_THRESH", "5000000"))
    BEACON_PERIOD_SEC:  int   = int(os.getenv("BEACON_PERIOD_SEC", "300"))
    BEACON_MIN_HITS:    int   = int(os.getenv("BEACON_MIN_HITS", "8"))


settings         = SystemConfig()
scanner_settings = ScannerConfig()
agent_settings   = AgentConfig()
packet_settings  = PacketConfig()
