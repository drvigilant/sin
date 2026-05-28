"""
sin.shutdown - Graceful shutdown coordination for the SIN API

Handles SIGTERM/SIGINT signals (e.g. from Docker / Kubernetes) and
coordinates an orderly teardown of long-running resources:
  - PacketSniffer thread
  - In-flight background scans (Redis state flag cleared)
  - Any future resources that register themselves via `add_shutdown_hook`

Usage (in server.py startup event):
    from sin.shutdown import register_handlers
    register_handlers(app)
"""

import asyncio
import signal
import os
from typing import Callable, Awaitable, List

from sin.utils.logger import get_logger

logger = get_logger("sin.shutdown")

# ── Registry of async shutdown hooks ─────────────────────────────────────────
_hooks: List[Callable[[], Awaitable[None]]] = []
_shutdown_event = asyncio.Event()


def add_shutdown_hook(coro_fn: Callable[[], Awaitable[None]]) -> None:
    """Register an async callable to be awaited during shutdown."""
    _hooks.append(coro_fn)


def is_shutting_down() -> bool:
    """Returns True once a shutdown signal has been received."""
    try:
        return _shutdown_event.is_set()
    except RuntimeError:
        return False


async def _run_shutdown_hooks() -> None:
    """Await every registered hook in registration order."""
    for hook in _hooks:
        try:
            await hook()
        except Exception as exc:
            logger.error(f"[shutdown] hook {hook.__name__!r} raised: {exc}")


def _signal_handler(signum: int, _frame) -> None:  # noqa: ANN001
    sig_name = signal.Signals(signum).name
    logger.info(f"[shutdown] Received {sig_name} – initiating graceful shutdown")
    # Schedule the async teardown from the synchronous signal handler
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(_run_shutdown_hooks())
            loop.call_soon_threadsafe(_shutdown_event.set)
        else:
            # Fallback for non-async contexts (e.g. tests)
            _shutdown_event.set()
    except RuntimeError:
        pass


def register_handlers() -> None:
    """
    Install SIGTERM and SIGINT handlers.
    Call this once inside @app.on_event("startup").
    """
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)
    logger.info("[shutdown] Signal handlers registered (SIGTERM, SIGINT)")
