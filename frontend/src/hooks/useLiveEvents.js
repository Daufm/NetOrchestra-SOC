import { useEffect, useRef, useState } from "react";
import { getAccessToken, refreshAccessToken } from "../api/client.js";

function socketUrl() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/api/ws`;
}

export function useLiveEvents(onResync, onEvent) {
  const [events, setEvents] = useState([]);
  const [status, setStatus] = useState("offline");
  const socketRef = useRef(null);
  const reconnectRef = useRef(null);
  const stoppedRef = useRef(false);
  const seenIdsRef = useRef(new Set());

  useEffect(() => {
    stoppedRef.current = false;
    let reconnectDelay = 1000;

    function connect() {
      if (stoppedRef.current || !getAccessToken()) {
        setStatus("offline");
        return;
      }
      setStatus("connecting");
      const socket = new WebSocket(socketUrl());
      socketRef.current = socket;
      socket.onopen = () => {
        reconnectDelay = 1000;
        setStatus("online");
        socket.send(JSON.stringify({ type: "auth", token: getAccessToken() }));
      };
      socket.onmessage = async (message) => {
        let payload;
        try {
          payload = JSON.parse(message.data);
        } catch {
          return;
        }
        if (payload.type === "auth_ok") return;
        if (payload.type === "resync") {
          onResync?.(payload.missed);
          return;
        }
        if (payload.type === "error" && payload.code === "token_expired") {
          try {
            await refreshAccessToken();
          } catch {
            setStatus("offline");
            return;
          }
          socket.close();
          return;
        }
        if (payload.id && payload.type) {
          if (seenIdsRef.current.has(payload.id)) return;
          seenIdsRef.current.add(payload.id);
          if (seenIdsRef.current.size > 500) {
            const oldest = seenIdsRef.current.values().next().value;
            seenIdsRef.current.delete(oldest);
          }
          setEvents((previous) => [payload, ...previous].slice(0, 100));
          onEvent?.(payload);
        }
      };
      socket.onerror = () => setStatus("offline");
      socket.onclose = () => {
        if (stoppedRef.current || socketRef.current !== socket) return;
        setStatus("reconnecting");
        reconnectRef.current = window.setTimeout(connect, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 15000);
      };
    }

    connect();
    return () => {
      stoppedRef.current = true;
      if (reconnectRef.current) window.clearTimeout(reconnectRef.current);
      socketRef.current?.close();
    };
  }, [onEvent, onResync]);

  return { events, status };
}
