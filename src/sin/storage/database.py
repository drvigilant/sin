from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sin.core.config import settings

# In a real setup, fetch this from os.getenv
DATABASE_URL = "postgresql://sin_user:secure_dev_password@localhost:5432/sin_network_db"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    """Dependency to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
