#!/usr/bin/env python3
import click
import socket
from sin.agent.runner import AgentRunner
from sin.utils.logger import get_logger

logger = get_logger("sin.cli")

def detect_local_subnet() -> str:
    """Auto-detects the local interface subnet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Dummy connection to determine interface (no actual packet sent)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        return ".".join(local_ip.split(".")[:-1])
    except Exception as e:
        logger.critical(f"Network interface detection failed: {e}")
        raise
    finally:
        s.close()

@click.group()
def cli():
    """
    SIN - Shadows In The Network
    Enterprise IoT Security Agent
    """
    pass

@cli.command()
@click.option('--subnet', help='Target subnet (e.g. 192.168.1). Defaults to local interface.')
@click.option('--output', default='data', help='Directory for report output.')
def scan(subnet, output):
    """
    Execute network discovery and vulnerability assessment.
    """
    target_subnet = subnet if subnet else detect_local_subnet()
    
    agent = AgentRunner()
    try:
        agent.run_assessment(target_subnet, output)
    except KeyboardInterrupt:
        logger.warning("Operation interrupted by user.")
    except Exception as e:
        logger.exception("Critical runtime failure")

if __name__ == '__main__':
    cli()
