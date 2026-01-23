from sin.storage.database import engine, Base
from sin.storage import models
from sin.utils.logger import get_logger

logger = get_logger("sin.storage.init")

def init_db():
    """Create tables if they don't exist."""
    logger.info("Initializing database schema...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized successfully.")
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}")
        raise
