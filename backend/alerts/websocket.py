"""
CampusShield AI — WebSocket Connection Manager
================================================
Manages WebSocket connections for real-time alert streaming.
"""

import json
import logging
import asyncio
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect
from jose import JWTError

from backend.auth.security import decode_token

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages active WebSocket connections.
    Supports authenticated connections and broadcast.
    """

    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, token: Optional[str] = None) -> bool:
        """
        Accept a WebSocket connection, optionally validating a JWT token.

        Args:
            websocket: The WebSocket connection
            token: Optional JWT for authentication

        Returns:
            True if connection accepted, False if rejected
        """
        # Validate token if provided
        if token:
            try:
                payload = decode_token(token)
                username = payload.get("sub", "anonymous")
                logger.info(f"WebSocket authenticated: {username}")
            except JWTError:
                logger.warning("WebSocket connection rejected: invalid token")
                await websocket.close(code=4001)
                return False

        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Active connections: {len(self.active_connections)}"
        )
        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket."""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Active connections: {len(self.active_connections)}"
        )

    async def broadcast(self, message: dict) -> None:
        """
        Send a message to all connected WebSocket clients.
        Automatically cleans up dead connections.
        """
        dead_connections = []
        async with self._lock:
            connections = list(self.active_connections)

        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)

        # Clean up dead connections
        if dead_connections:
            async with self._lock:
                for dc in dead_connections:
                    if dc in self.active_connections:
                        self.active_connections.remove(dc)
            logger.info(f"Cleaned up {len(dead_connections)} dead WebSocket connections")

    async def send_personal(self, websocket: WebSocket, message: dict) -> None:
        """Send a message to a specific WebSocket client."""
        try:
            await websocket.send_json(message)
        except Exception:
            await self.disconnect(websocket)

    @property
    def connection_count(self) -> int:
        return len(self.active_connections)


# Module-level singleton
manager = ConnectionManager()


async def broadcast_alert(alert_data: dict) -> None:
    """Convenience function to broadcast an alert to all clients."""
    await manager.broadcast(alert_data)


async def broadcast_progress(progress_data: dict) -> None:
    """Broadcast processing progress updates."""
    await manager.broadcast({
        "type": "progress",
        **progress_data,
    })
