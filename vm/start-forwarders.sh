#!/usr/bin/env bash
pkill -f 'socat.*8081' 2>/dev/null || true
pkill -f 'socat.*18081' 2>/dev/null || true
sleep 1

socat TCP-LISTEN:8081,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:8080 &
socat TCP-LISTEN:18081,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:18080 &
sleep 2

echo "socat forwarders started"
curl -s -o /dev/null -w "8081->8080: %{http_code}\n" http://127.0.0.1:8081/
curl -s -o /dev/null -w "18081->18080: %{http_code}\n" http://127.0.0.1:18081/api/status
