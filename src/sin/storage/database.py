import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Configuration: Check if we are in Docker (using env var) or Local
DB_USER = os.getenv("POSTGRES_USER", "sin_user")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "secure_dev_password")
DB_NAME = os.getenv("POSTGRES_DB", "sin_network_db")
DB_HOST = os.getenv("SIN_DB_HOST", "localhost")  # Default to localhost if not in Docker

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
