#!/usr/bin/env bash
set -euo pipefail

# Remove old macflow rules (idempotent)
while ip -4 rule show | grep -q 'fwmark .* lookup .* # macflow'; do
  rid=$(ip -4 rule show | awk '/# macflow/ {print $1; exit}' | tr -d ':')
  ip -4 rule del pref "$rid" || true
done

ip -4 rule add pref 20000 fwmark 0x100 lookup 100 # macflow
ip -4 route replace table 100 default via 10.0.1.2
ip -4 rule add pref 20010 fwmark 0x101 lookup 101 # macflow
ip -4 route replace table 101 default via 10.0.1.2
