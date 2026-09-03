import json
import asyncio
from typing import List, Dict, Any
from fastapi import WebSocket

class WebSocketConnectionManager:
    """
    Quản lý tập trung các kết nối WebSocket client (SOC Web Consoles)
    và cung cấp hàm phát sóng sự kiện thời gian thực (Broadcast).
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """
        Phát sóng sự kiện JSON tới tất cả các màn hình SOC đang mở:
        event_type: 'NEW_ALERT', 'PENDING_APPROVAL', 'APPROVAL_RESOLVED', 'TARGET_UNBLOCKED', v.v.
        """
        if not self.active_connections:
            return

        payload = {
            "event": event_type,
            "data": data
        }
        message_str = json.dumps(payload, default=str)

        disconnected = []
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message_str)
            except Exception:
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

ws_manager = WebSocketConnectionManager()
