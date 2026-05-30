"""
sin.storage.init_db
═══════════════════
Creates or migrates the database schema on startup.

Enterprise fix in this revision
─────────────────────────────────
ADDED:  Safe column migration for existing deployments.
        SQLAlchemy's create_all() only creates missing *tables* — it does not
        add new columns to existing tables.  Running this after a schema change
        on a live database would leave the new columns missing, causing
        AttributeError at runtime when runner.py tries to write risk_score etc.

        _apply_migrations() issues ALTER TABLE … ADD COLUMN IF NOT EXISTS for
        every new column.  It is:
          • Idempotent  — safe to run on every startup
          • Non-destructive — never drops or modifies existing columns
          • Backend-aware — uses Postgres syntax by default, SQLite fallback
"""

from __future__ import annotations

from sin.storage.database import Base, engine
from sin.storage import models
from sin.storage import credential_vault  # noqa: F401  # noqa: F401 — registers models with Base.metadata
from sin.utils.logger import get_logger

logger = get_logger("sin.storage.init")

# New columns added to device_logs in this revision.
# Format: (column_name, DDL_type_string, default_expression_or_None)
_DEVICE_LOG_NEW_COLUMNS = [
    ("mac_address",  "VARCHAR",   None),
    ("device_type",  "VARCHAR",   None),
    ("risk_score",   "INTEGER",   "0"),
    ("risk_level",   "VARCHAR",   "'UNKNOWN'"),
    ("risk_reasons", "JSON",      "'[]'"),
    ("jarm_hash",    "VARCHAR",   None),
    ("first_seen",   "TIMESTAMP", "NOW()"),
    ("last_seen",    "TIMESTAMP", "NOW()"),
    ("telemetry",    "JSON",      "'{}'"),
    ("firmware",     "VARCHAR",   None),
    ("serial_number","VARCHAR",   None),
    ("model", "VARCHAR", None),
]

# New columns for security_events (description widened to TEXT)
_SECURITY_EVENT_NEW_COLUMNS: list = []  # description already TEXT in new installs

# device_baselines table is created by create_all() — no ALTER TABLE needed.
# Listed here for documentation; kept as empty list.
_DEVICE_BASELINE_NEW_COLUMNS: list = []


def _apply_migrations() -> None:
    """
    Safely add new columns to existing tables.
    Uses ADD COLUMN IF NOT EXISTS (Postgres 9.6+).
    For SQLite (which lacks IF NOT EXISTS), catches and ignores
    'duplicate column' errors.
    """
    import os
    backend = os.getenv("SIN_DB_BACKEND", "postgres").lower()

    with engine.connect() as conn:
        for col_name, col_type, col_default in _DEVICE_LOG_NEW_COLUMNS:
            try:
                if backend == "sqlite":
                    # SQLite does not support IF NOT EXISTS on ALTER TABLE
                    ddl = f"ALTER TABLE device_logs ADD COLUMN {col_name} {col_type}"
                    if col_default:
                        ddl += f" DEFAULT {col_default}"
                else:
                    ddl = (
                        f"ALTER TABLE device_logs "
                        f"ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
                    )
                    if col_default:
                        ddl += f" DEFAULT {col_default}"

                conn.execute(__import__("sqlalchemy").text(ddl))
                conn.commit()
                logger.debug(f"Migration OK: device_logs.{col_name}")

            except Exception as exc:
                # SQLite raises OperationalError "duplicate column name"
                # Postgres raises ProgrammingError if column exists without IF NOT EXISTS
                err = str(exc).lower()
                if "duplicate column" in err or "already exists" in err:
                    logger.debug(f"Column device_logs.{col_name} already exists — skipped")
                    conn.rollback()
                else:
                    logger.warning(f"Migration warning for {col_name}: {exc}")
                    conn.rollback()




def _seed_admin() -> None:
    """Create default admin user on first startup if no users exist."""
    import os
    from sin.storage.database import SessionLocal
    from sin.storage.models import User
    from sin.api.auth import hash_password

    username = os.getenv("SIN_ADMIN_USER", "admin")
    password = os.getenv("SIN_ADMIN_PASS", "sinisboom")

    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            db.add(User(
                username=username,
                hashed_password=hash_password(password),
                role="admin",
                is_active="true",
            ))
            db.commit()
            logger.info(f"Admin user seeded: {username}")
        else:
            logger.debug("Users already exist — skipping seed")
    except Exception as exc:
        logger.warning(f"Admin seed failed: {exc}")
        db.rollback()
    finally:
        db.close()

def init_db() -> None:
    """
    Create all tables (new installs) then apply column migrations (upgrades).
    Safe to call on every application startup.
    """
    logger.info("Initialising database schema...")
    try:
        # Step 1 — create any tables that don't exist yet
        Base.metadata.create_all(bind=engine)
        logger.info("Tables verified / created.")

        # Step 2 — add new columns to existing tables
        _apply_migrations()
        logger.info("Column migrations applied.")

        # Step 3 — seed default admin
        _seed_admin()

    except Exception as exc:
        logger.critical(f"Database initialisation failed: {exc}")
        raise
