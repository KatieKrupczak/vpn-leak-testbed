#!/usr/bin/env bash
set -euo pipefail

URL_FILE="${URL_FILE:-/tests/urls.txt}"
OUTDIR="${OUTDIR:-/results}"
mkdir -p "$OUTDIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/traffic-$TIMESTAMP.pcap"

# Start tcpdump once (capture all traffic)
echo "Starting tcpdump -> $PCAP"
tcpdump -i any -s 0 -w "$PCAP" -U &>/dev/null &
TCPDUMP_PID=$!

trap 'kill $TCPDUMP_PID 2>/dev/null || true' EXIT

# Wait for VPN tunnel (tun0) to appear
echo "Waiting for VPN (tun0) to come up..."
# change interface name if your VPN uses a different interface
while ! ip addr show tun0 &>/dev/null; do
  sleep 1
done
echo "VPN tunnel is up."

echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# echo "=== VPN Diagnostics ==="
# echo "Default route:"
# ip route
# echo
# echo "Interfaces:"
# ip addr show
# echo
# echo "DNS resolvers:"
# cat /etc/resolv.conf
# echo
# echo "Test connectivity to public IP:"
# ping -c 3 1.1.1.1 || echo "Ping failed"
# echo
# echo "Test HTTPS request:"
# curl -v https://ifconfig.me || echo "Curl failed"
# echo "=== End VPN Diagnostics ==="
# echo

# List of URLs (exact) for which to run the headless WebRTC probe.
# Edit this list to include only the sites you want to test for leaks.
WEBRTC_URLS=(
  "https://meet.google.com"
  "https://example.com"
)

# Read URLs and visit
while IFS= read -r url || [ -n "$url" ]; do
  # trim whitespace and skip empty/comment lines
  url="$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -z "$url" ] && continue
  [[ $url == \#* ]] && continue

  echo "Visiting: $url"
  # Simple fetch to exercise site
  curl -s -L --max-time 30 "$url" >/dev/null || echo "curl failed for $url"

  # If url matches any entry in WEBRTC_URLS, run headless webrtc probe
  for w in "${WEBRTC_URLS[@]}"; do
    if [ "$url" = "$w" ]; then
      echo "  -> Running headless WebRTC probe for $url"
      # run the wrtc script; it will produce network traffic to capture
      if ! timeout 30s node /agent/webrtc_check.js >/dev/null 2>&1; then
        echo "  -> WebRTC probe timed out or failed for $url"
      fi
      break
    fi
  done

  sleep 1
done < "$URL_FILE"

# Stop tcpdump and wait for it to finish writing
echo "Stopping tcpdump"
kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "Done. Combined pcap: $PCAP"

tail -f /dev/null
