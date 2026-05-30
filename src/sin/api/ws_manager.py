"""
sin.api.ws_manager
══════════════════
Scalable WebSocket event broker using Redis Pub/Sub.

Architecture:
  - ONE shared aioredis connection pool per API process
  - ONE background task subscribes to sin:ws:stream and fans out to all
    connected WebSocket clients in that process
  - Celery workers / scanner / runner publish to sin:ws:stream via sync redis
  - Any number of Uvicorn workers scale horizontally — each maintains its own
    pool + fan-out task, all receiving the same Redis messages

This replaces the previous pattern where each WebSocket connection opened
its own Redis connection (O(n) connections per process).

Publishing (from sync code — scanner, runner, celery):
    from sin.api.ws_manager import publish_event
    publish_event("SCAN_COMPLETE", {"total": 20})

Publishing (from async code — server.py endpoints):
    from sin.api.ws_manager import publish_event_async
    await publish_event_async("MITIGATION", {"ip": "192.168.1.5"})

WebSocket endpoint:
    from sin.api.ws_manager import ws_manager
    await ws_manager.connect(websocket)  # blocks until disconnect
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Set

import aioredis
import redis as _sync_redis
from fastapi import WebSocket, WebSocketDisconnect
from sin.utils.logger import get_logger

logger = get_logger("sin.api.ws_manager")

REDIS_HOST     = os.getenv("SIN_REDIS_HOST", "redis")
REDIS_PORT     = int(os.getenv("SIN_REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("SIN_REDIS_PASSWORD", "") or None
CHANNEL        = "sin:ws:stream"


class WebSocketManager:
    """
    Manages all WebSocket connections for one API process.
    One Redis subscriber fan-out, N WebSocket clients.
    """

    def __init__(self) -> None:
        self._clients: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._pool: aioredis.Redis | None = None
        self._listener_task: asyncio.Task | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def startup(self) -> None:
        """Call from FastAPI startup event."""
        self._pool = aioredis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            decode_responses=True,
            max_connections=10,
        )
        self._listener_task = asyncio.create_task(self._listen())
        logger.info(f"[ws_manager] Redis Pub/Sub listener started on {REDIS_HOST}:{REDIS_PORT}/{CHANNEL}")

    async def shutdown(self) -> None:
        """Call from FastAPI shutdown event."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        if self._pool:
            await self._pool.close()
        logger.info("[ws_manager] Shutdown complete.")

    # ── Client management ─────────────────────────────────────────────────────

    async def connect(self, websocket: WebSocket) -> None:
        """
        Accept a WebSocket, register it, and block until it disconnects.
        This is the entire WebSocket endpoint handler.
        """
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)
        client_count = len(self._clients)
        logger.info(f"[ws_manager] Client connected. Total: {client_count}")

        try:
            # Keep the connection alive — client just listens
            while True:
                # Ping every 30s to detect dead connections before Redis does
                await asyncio.sleep(30)
                await websocket.send_json({"type": "PING", "ts": datetime.now(timezone.utc).isoformat()})
        except (WebSocketDisconnect, Exception):
            pass
        finally:
            async with self._lock:
                self._clients.discard(websocket)
            logger.info(f"[ws_manager] Client disconnected. Total: {len(self._clients)}")

    # ── Fan-out listener ──────────────────────────────────────────────────────

    async def _listen(self) -> None:
        """
        Single background task: subscribes to Redis, fans out to all clients.
        Reconnects automatically on Redis disconnect.
        """
        while True:
            pubsub = None
            try:
                pubsub = self._pool.pubsub()
                await pubsub.subscribe(CHANNEL)
                logger.info(f"[ws_manager] Subscribed to {CHANNEL}")

                async for message in pubsub.listen():
                    if message["type"] != "message":
                        continue
                    try:
                        data = json.loads(message["data"])
                    except (json.JSONDecodeError, TypeError):
                        continue

                    # Fan out to all connected clients concurrently
                    async with self._lock:
                        clients = list(self._clients)

                    if not clients:
                        continue

                    results = await asyncio.gather(
                        *[self._send_safe(ws, data) for ws in clients],
                        return_exceptions=True,
                    )

                    # Remove dead clients
                    dead = {clients[i] for i, r in enumerate(results) if isinstance(r, Exception)}
                    if dead:
                        async with self._lock:
                            self._clients -= dead

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"[ws_manager] Listener error, reconnecting in 2s: {e}")
                await asyncio.sleep(2)
            finally:
                if pubsub:
                    try:
                        await pubsub.unsubscribe(CHANNEL)
                        await pubsub.close()
                    except Exception:
                        pass

    @staticmethod
    async def _send_safe(ws: WebSocket, data: dict) -> None:
        await ws.send_json(data)

    # ── Async publish (from endpoint handlers) ────────────────────────────────

    async def publish(self, event_type: str, message: object) -> None:
        """Publish from async context (FastAPI endpoints)."""
        if not self._pool:
            return
        payload = json.dumps({
            "type": event_type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        try:
            await self._pool.publish(CHANNEL, payload)
        except Exception as e:
            logger.debug(f"[ws_manager] async publish failed: {e}")


# ── Process-level singleton ───────────────────────────────────────────────────
ws_manager = WebSocketManager()


# ── Sync publish (for scanner/runner/celery workers) ─────────────────────────

def publish_event(event_type: str, message: object) -> None:
    """
    Publish from synchronous code (scanner, runner, Celery tasks).
    Uses a short-lived sync Redis connection — no event loop required.
    """
    try:
        r = _sync_redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            password=REDIS_PASSWORD,
            socket_connect_timeout=2,
            decode_responses=True,
        )
        payload = json.dumps({
            "type": event_type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        r.publish(CHANNEL, payload)
        r.close()
    except Exception as e:
        logger.debug(f"[ws_manager] sync publish failed: {e}")
