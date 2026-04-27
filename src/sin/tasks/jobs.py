from sin.tasks.celery_app import celery_app
from sin.agent.runner import AgentRunner
from sin.utils.logger import get_logger

logger = get_logger("sin.tasks.jobs")

@celery_app.task(name="run_network_scan", bind=True, max_retries=0)
def run_network_scan(self, subnet: str = "192.168.30.0/24"):
    logger.info(f"⏳ Starting scheduled scan for {subnet}...")
    try:
        runner = AgentRunner()
        runner.run_assessment(subnet)
        logger.info("✅ Scheduled scan completed successfully.")
        return "Scan Complete"
    except Exception as e:
        logger.error(f"❌ Scheduled scan failed: {e}")
        return "Scan Failed"
