from sin.tasks.celery_app import celery_app
from sin.agent.runner import AgentRunner
from sin.utils.logger import get_logger

logger = get_logger("sin.tasks.jobs")

@celery_app.task(name="run_network_scan")
def run_network_scan(subnet: str = "172.21.41.0/24"):
    """
    Background task to run a full network assessment.
    """
    logger.info(f"⏳ Starting scheduled scan for {subnet}...")
    try:
        runner = AgentRunner()
        # reusing the logic we wrote on Day 2 & 3
        runner.run_assessment(subnet)
        logger.info("✅ Scheduled scan completed successfully.")
        return "Scan Complete"
    except Exception as e:
        logger.error(f"❌ Scheduled scan failed: {e}")
        return "Scan Failed"
