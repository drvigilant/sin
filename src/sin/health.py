"""
sin.health - Service health checks for all dependencies
"""
from sin.utils.logger import get_logger
import redis
import os
from sqlalchemy import text
from sin.storage.database import SessionLocal

logger = get_logger("sin.health")

def check_database() -> dict:
    """Check PostgreSQL connection"""
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        return {"status": "healthy", "service": "postgresql"}
    except Exception as e:
        logger.error(f"Database check failed: {e}")
        return {"status": "unhealthy", "service": "postgresql", "error": str(e)}

def check_redis() -> dict:
    """Check Redis connection"""
    try:
        r = redis.Redis(
            host=os.getenv("SIN_REDIS_HOST", "redis"),
            port=int(os.getenv("SIN_REDIS_PORT", "6379")),
            password=os.getenv("SIN_REDIS_PASSWORD", ""),
            socket_connect_timeout=2
        )
        r.ping()
        return {"status": "healthy", "service": "redis"}
    except Exception as e:
        logger.error(f"Redis check failed: {e}")
        return {"status": "unhealthy", "service": "redis", "error": str(e)}

def check_all() -> dict:
    """Check all critical services"""
    db_health = check_database()
    redis_health = check_redis()
    
    all_healthy = (
        db_health["status"] == "healthy" and 
        redis_health["status"] == "healthy"
    )
    
    return {
        "status": "healthy" if all_healthy else "degraded",
        "services": [db_health, redis_health],
        "timestamp": __import__("datetime").datetime.utcnow().isoformat()
    }
