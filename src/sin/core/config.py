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

settings         = SystemConfig()
scanner_settings = ScannerConfig()
