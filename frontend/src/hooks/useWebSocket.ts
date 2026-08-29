/**
 * WebSocket hook for real-time event streaming.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import { createWebSocket } from '../services/api';
import type { WSMessage } from '../types';

type MessageHandler = (message: WSMessage) => void;

interface UseWebSocketOptions {
  onMessage?: MessageHandler;
  reconnectInterval?: number;
  maxRetries?: number;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { onMessage, reconnectInterval = 3000, maxRetries = 5 } = options;
  const [isConnected, setIsConnected] = useState(false);
  const [reconnectCount, setReconnectCount] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);
  const pingInterval = useRef<number | undefined>(undefined);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = createWebSocket();
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      retryRef.current = 0;
      setReconnectCount(0);

      // Keepalive ping every 30s
      pingInterval.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping');
        }
      }, 30000);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        onMessage?.(msg);
      } catch {
        // Ignore parse errors
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      clearInterval(pingInterval.current);

      if (retryRef.current < maxRetries) {
        retryRef.current += 1;
        setReconnectCount(retryRef.current);
        setTimeout(connect, reconnectInterval);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [onMessage, reconnectInterval, maxRetries]);

  useEffect(() => {
    connect();
    return () => {
      clearInterval(pingInterval.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const sendMessage = useCallback((data: unknown) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  return { isConnected, reconnectCount, sendMessage };
}
