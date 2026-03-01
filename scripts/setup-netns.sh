#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-}"
ROUTER_NS="ns-router"
WAN_NS="ns-wan"
LAN_NS="ns-lan"

up() {
  ip netns add "${ROUTER_NS}" || true
  ip netns add "${WAN_NS}" || true
  ip netns add "${LAN_NS}" || true

  ip link add veth-r-w type veth peer name veth-w-r || true
  ip link add veth-r-l type veth peer name veth-l-r || true

  ip link set veth-r-w netns "${ROUTER_NS}"
  ip link set veth-w-r netns "${WAN_NS}"
  ip link set veth-r-l netns "${ROUTER_NS}"
  ip link set veth-l-r netns "${LAN_NS}"

  ip netns exec "${ROUTER_NS}" ip addr replace 10.0.1.1/24 dev veth-r-w
  ip netns exec "${WAN_NS}" ip addr replace 10.0.1.2/24 dev veth-w-r

  ip netns exec "${ROUTER_NS}" ip addr replace 192.168.50.1/24 dev veth-r-l
  ip netns exec "${LAN_NS}" ip addr replace 192.168.50.2/24 dev veth-l-r

  ip netns exec "${ROUTER_NS}" ip link set lo up
  ip netns exec "${WAN_NS}" ip link set lo up
  ip netns exec "${LAN_NS}" ip link set lo up
  ip netns exec "${ROUTER_NS}" ip link set veth-r-w up
  ip netns exec "${WAN_NS}" ip link set veth-w-r up
  ip netns exec "${ROUTER_NS}" ip link set veth-r-l up
  ip netns exec "${LAN_NS}" ip link set veth-l-r up

  ip netns exec "${LAN_NS}" ip route replace default via 192.168.50.1
  ip netns exec "${ROUTER_NS}" ip route replace default via 10.0.1.2

  ip netns exec "${ROUTER_NS}" sysctl -w net.ipv4.ip_forward=1 >/dev/null

  # Simulate two clients by adding macvlan interfaces in LAN ns.
  ip netns exec "${LAN_NS}" ip link add managed0 link veth-l-r type macvlan mode bridge || true
  ip netns exec "${LAN_NS}" ip link add normal0 link veth-l-r type macvlan mode bridge || true

  ip netns exec "${LAN_NS}" ip link set managed0 address 02:AA:BB:CC:DD:01
  ip netns exec "${LAN_NS}" ip link set normal0 address 02:AA:BB:CC:DD:03

  ip netns exec "${LAN_NS}" ip addr replace 192.168.50.11/24 dev managed0
  ip netns exec "${LAN_NS}" ip addr replace 192.168.50.12/24 dev normal0

  ip netns exec "${LAN_NS}" ip link set managed0 up
  ip netns exec "${LAN_NS}" ip link set normal0 up

  echo "[setup-netns] up complete"
}

down() {
  ip netns del "${LAN_NS}" 2>/dev/null || true
  ip netns del "${WAN_NS}" 2>/dev/null || true
  ip netns del "${ROUTER_NS}" 2>/dev/null || true
  echo "[setup-netns] down complete"
}

case "${ACTION}" in
  up)
    up
    ;;
  down)
    down
    ;;
  *)
    echo "Usage: $0 <up|down>"
    exit 1
    ;;
esac
