import json
import os
from datetime import datetime
from typing import Dict
from sin.discovery.network import NetworkDiscovery
from sin.utils.logger import get_logger

logger = get_logger("sin.agent.runner")

class AgentRunner:
    """
    Primary execution controller for the SIN security agent.
    """
    
    def __init__(self):
        self.discovery_module = NetworkDiscovery()
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    def run_assessment(self, subnet: str, output_dir: str = "data") -> None:
        """
        Executes a full assessment cycle: Discovery -> Analysis -> Storage.
        """
        logger.info(f"Starting assessment session: {self.session_id}")
        
        # Phase 1: Discovery
        assets = self.discovery_module.execute_subnet_scan(subnet)
        
        # Phase 2: Report Generation (Basic persistence for Day 1)
        report = {
            "metadata": {
                "session_id": self.session_id,
                "timestamp": datetime.utcnow().isoformat(),
                "agent_version": "0.1.0"
            },
            "network_topology": {
                "target_subnet": subnet,
                "total_hosts": len(assets)
            },
            "assets": assets
        }
        
        self._persist_data(report, output_dir)

    def _persist_data(self, data: Dict, directory: str) -> None:
        if not os.path.exists(directory):
            os.makedirs(directory)
            
        filepath = os.path.join(directory, f"scan_report_{self.session_id}.json")
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            logger.info(f"Assessment report successfully serialized to {filepath}")
        except IOError as e:
            logger.error(f"Failed to persist report: {e}")
