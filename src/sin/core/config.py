import os
from dataclasses import dataclass
from typing import List

@dataclass
class SystemConfig:
    APP_NAME: str = "SIN"
    VERSION: str = "0.1.0-alpha"
    ENV: str = os.getenv("SIN_ENV", "development")
    LOG_LEVEL: str = os.getenv("SIN_LOG_LEVEL", "INFO")
    
@dataclass
class ScannerConfig:
    DEFAULT_THREADS: int = 50
    TIMEOUT: float = 1.0
    COMMON_PORTS: List[int] = None

    def __post_init__(self):
        if self.COMMON_PORTS is None:
            self.COMMON_PORTS = [21, 22, 23, 80, 443, 8080, 1883, 502]

settings = SystemConfig()
scanner_settings = ScannerConfig()
