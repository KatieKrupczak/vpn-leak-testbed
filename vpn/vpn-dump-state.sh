#!/bin/sh
# vpn-dump-state.sh - optional debug script

set -eu

echo "[vpn-state] ===== IP ADDRESSES ====="
ip addr show | sed 's/^/[vpn-state] /'

echo "[vpn-state] ===== IPv4 ROUTES ====="
ip route show | sed 's/^/[vpn-state] /'

echo "[vpn-state] ===== IPv6 ROUTES ====="
ip -6 route show || true

# If you want to be extra:
if command -v iptables >/dev/null 2>&1; then
  echo "[vpn-state] ===== iptables -S (filter) ====="
  iptables -S | sed 's/^/[vpn-state] /'
fi

if command -v ip6tables >/dev/null 2>&1; then
  echo "[vpn-state] ===== ip6tables -S (filter) ====="
  ip6tables -S | sed 's/^/[vpn-state] /'
fi
