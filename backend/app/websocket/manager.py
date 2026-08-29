"""
WebSocket Connection Manager
Manages real-time event broadcasting to connected clients.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


def _serialize(obj):
    """JSON serializer for objects not serializable by default json."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


class ConnectionManager:
    """
    Manages WebSocket connections with room/topic support.
    Supports broadcasting to all clients or specific rooms.
    """
    
    def __init__(self):
        # All active connections
        self._connections: Dict[str, WebSocket] = {}  # client_id → socket
        # Room subscriptions
        self._rooms: Dict[str, Set[str]] = {}  # room → set of client_ids
        self._client_rooms: Dict[str, Set[str]] = {}  # client_id → set of rooms
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, client_id: str, rooms: List[str] = None):
        """Accept a new WebSocket connection and subscribe to rooms."""
        await websocket.accept()
        
        async with self._lock:
            self._connections[client_id] = websocket
            self._client_rooms[client_id] = set(rooms or ["global"])
            
            for room in (rooms or ["global"]):
                if room not in self._rooms:
                    self._rooms[room] = set()
                self._rooms[room].add(client_id)
        
        logger.info(f"Client {client_id} connected (rooms: {rooms}). Total: {len(self._connections)}")
        
        # Send connection acknowledgment
        await self.send_to_client(client_id, {
            "type": "connected",
            "client_id": client_id,
            "rooms": list(rooms or ["global"]),
        })
    
    async def disconnect(self, client_id: str):
        """Remove a client and clean up room subscriptions."""
        async with self._lock:
            if client_id in self._connections:
                del self._connections[client_id]
            
            rooms = self._client_rooms.pop(client_id, set())
            for room in rooms:
                if room in self._rooms:
                    self._rooms[room].discard(client_id)
                    if not self._rooms[room]:
                        del self._rooms[room]
        
        logger.info(f"Client {client_id} disconnected. Total: {len(self._connections)}")
    
    async def send_to_client(self, client_id: str, data: dict):
        """Send message to a specific client."""
        ws = self._connections.get(client_id)
        if ws:
            try:
                await ws.send_text(json.dumps(data, default=_serialize))
            except Exception as e:
                logger.error(f"Failed to send to client {client_id}: {e}")
                await self.disconnect(client_id)
    
    async def broadcast(self, data: dict, room: str = "global"):
        """Broadcast a message to all clients in a room."""
        client_ids = list(self._rooms.get(room, set()))
        if not client_ids:
            return
        
        message = json.dumps(data, default=_serialize)
        failed = []
        
        for client_id in client_ids:
            ws = self._connections.get(client_id)
            if ws:
                try:
                    await ws.send_text(message)
                except Exception as e:
                    logger.debug(f"Broadcast failed for {client_id}: {e}")
                    failed.append(client_id)
        
        # Clean up dead connections
        for client_id in failed:
            await self.disconnect(client_id)
    
    async def broadcast_all(self, data: dict):
        """Broadcast to every connected client."""
        client_ids = list(self._connections.keys())
        message = json.dumps(data, default=_serialize)
        failed = []
        
        for client_id in client_ids:
            ws = self._connections.get(client_id)
            if ws:
                try:
                    await ws.send_text(message)
                except Exception:
                    failed.append(client_id)
        
        for client_id in failed:
            await self.disconnect(client_id)
    
    async def broadcast_event(self, event: dict):
        """Broadcast a new security event."""
        await self.broadcast_all({"type": "new_event", "data": event})
    
    async def broadcast_alert(self, alert: dict):
        """Broadcast a new alert."""
        await self.broadcast_all({"type": "new_alert", "data": alert})
    
    async def broadcast_incident(self, incident: dict, action: str = "created"):
        """Broadcast an incident update."""
        await self.broadcast_all({
            "type": "incident_update",
            "action": action,
            "data": incident,
        })
    
    async def broadcast_stats_update(self, stats: dict):
        """Broadcast updated dashboard statistics."""
        await self.broadcast_all({"type": "stats_update", "data": stats})
    
    @property
    def connection_count(self) -> int:
        return len(self._connections)
    
    def get_room_info(self) -> dict:
        return {
            "total_connections": len(self._connections),
            "rooms": {room: len(clients) for room, clients in self._rooms.items()},
        }


# Module-level singleton
ws_manager = ConnectionManager()
