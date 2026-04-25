"""
src/sin/storage/database.py
────────────────────────────
SQLAlchemy engine + session factory.

Env var priority (highest → lowest):
  1. SIN_DB_*      — set by docker-compose environment: block
  2. POSTGRES_*    — set by the postgres service itself
  3. Hardcoded fallback — only used in local dev without Docker

This order means docker-compose, bare Pi, and local dev all work
without touching this file.
"""
import os

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import declarative_base, sessionmaker

# ── Connection parameters ─────────────────────────────────────────────────────
# Read SIN_DB_* first (passed by docker-compose), fall back to POSTGRES_* vars.
# Never use a hardcoded password as a default — fail loudly instead.

DB_USER = os.getenv("SIN_DB_USER") or os.getenv("POSTGRES_USER") or "sin_user"
DB_PASS = os.getenv("SIN_DB_PASSWORD") or os.getenv("POSTGRES_PASSWORD") or ""
DB_NAME = os.getenv("SIN_DB_NAME") or os.getenv("POSTGRES_DB") or "sin_network_db"
DB_HOST = os.getenv("SIN_DB_HOST") or "localhost"
DB_PORT = os.getenv("SIN_DB_PORT", "5432")

if not DB_PASS:
    raise RuntimeError(
        "Database password not set. "
        "Set SIN_DB_PASSWORD (or POSTGRES_PASSWORD) in your .env file."
    )

# ── Backend selection ─────────────────────────────────────────────────────────
# SIN_DB_BACKEND=sqlite  → lightweight, zero-config, good for Pi dev
# SIN_DB_BACKEND=postgres (default in Docker) → full production backend

_backend = os.getenv("SIN_DB_BACKEND", "postgres").lower()

if _backend == "sqlite":
    _sqlite_path = os.getenv("SIN_SQLITE_PATH", "/var/lib/sin/sin.db")
    os.makedirs(os.path.dirname(_sqlite_path), exist_ok=True)
    DATABASE_URL = f"sqlite:///{_sqlite_path}"
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
    # Enable WAL mode for safe concurrent access on Pi
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA journal_mode=WAL")
        dbapi_conn.execute("PRAGMA synchronous=NORMAL")
else:
    DATABASE_URL = (
        f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    engine = create_engine(
        DATABASE_URL,
        echo=False,
        pool_pre_ping=True,      # detects stale connections automatically
        pool_size=5,
        max_overflow=10,
        pool_recycle=300,        # recycle connections every 5 min
    )

# ── Session factory ───────────────────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ── Base class for all ORM models ─────────────────────────────────────────────
Base = declarative_base()


def get_db():
    """FastAPI dependency — yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_connection() -> bool:
    """Returns True if the database is reachable. Used by health checks."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False

