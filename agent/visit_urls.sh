#!/usr/bin/env bash
set -euo pipefail

URL_FILE="${URL_FILE:-/tests/urls.txt}"
WEBRTC_FILE="${WEBRTC_FILE:-/tests/webrtc_urls.txt}"
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
while ! ip addr show tun0 &>/dev/null; do
  sleep 1
done
echo "VPN tunnel is up."

# Force DNS to public resolvers
echo "nameserver 1.1.1.1" > /etc/resolv.conf


# === IPv4 / IPv6 URL Tests ===
if [ -f "$URL_FILE" ]; then
  echo "Starting IPv4/IPv6 tests from $URL_FILE"
  while IFS= read -r url || [ -n "$url" ]; do
    url="$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$url" ] && continue
    [[ $url == \#* ]] && continue

    echo "Visiting (IPv4): $url"
    curl -4 -s -L --max-time 30 "$url" >/dev/null || echo "curl IPv4 failed for $url"

    # echo "Visiting (IPv6): $url"
    # curl -6 -s -L --max-time 30 "$url" >/dev/null || echo "curl IPv6 failed for $url"

    sleep 1
  done < "$URL_FILE"
else
  echo "No URL file found at $URL_FILE"
fi


# === WebRTC Tests ===
if [ -f "$WEBRTC_FILE" ]; then
  echo "Starting WebRTC tests from $WEBRTC_FILE"
  while IFS= read -r wurl || [ -n "$wurl" ]; do
    wurl="$(echo "$wurl" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$wurl" ] && continue
    [[ $wurl == \#* ]] && continue

    echo "Running WebRTC probe for $wurl"
    if ! timeout 30s node /agent/webrtc_check.js "$wurl" >/dev/null 2>&1; then
      echo "  -> WebRTC probe timed out or failed for $wurl"
    fi
    sleep 1
  done < "$WEBRTC_FILE"
  sleep 30
else
  echo "No WebRTC URL file found at $WEBRTC_FILE"
fi


# Stop tcpdump and wait for it to finish writing
echo "Stopping tcpdump"
kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "Done. Combined pcap: $PCAP"

# Keep container running for inspection
tail -f /dev/null
