#!/bin/sh
set -eu # Exit on error and undefined variable

# VPN_CONFIG is the path to the config inside the container
# We'll point it to a config under vpn/configs
# If not set, use default.ovpn
CONFIG="${VPN_CONFIG:-/etc/vpn/configs/default.ovpn}"

# Optional auth file (username/password) inside the container
AUTH="${VPN_AUTH_FILE:-}"

echo "[vpn] Using config: $CONFIG"

case "$CONFIG" in
  *.ovpn) 
    echo "[vpn] Starting OpenVPN..."
    if [ -n "$AUTH" ]; then
      echo "[vpn] Using auth file: $AUTH"
      openvpn --config "$CONFIG" --auth-user-pass "$AUTH" &
    else
      openvpn --config "$CONFIG" &
    fi
    VPN_PID=$!
    ;;
  *.conf) 
    echo "[vpn] Starting WireGuard..."
    wg-quick up "$CONFIG"
    VPN_PID=""
    ;;
  *) 
    echo "[vpn] Unsupported VPN config format: $CONFIG"
    exit 1
    ;;
esac

# Simple health loop: keep container running
echo "[vpn] VPN process started with PID: $VPN_PID, entering sleep loop."
while true; do
  sleep 60
done