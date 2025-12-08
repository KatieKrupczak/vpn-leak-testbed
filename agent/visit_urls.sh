#!/usr/bin/env bash
set -euo pipefail

URL_FILE="${URL_FILE:-/tests/urls.txt}"
WEBRTC_FILE="${WEBRTC_FILE:-/tests/webrtc_urls.txt}"
QUIC_FILE="${QUIC_FILE:-/tests/quic_urls.txt}"
OUTDIR="${OUTDIR:-/results}"
IFACE="${VPN_IFACE:-tun0}"
CFG="${VPN_CONFIG:-/etc/vpn/configs/default.ovpn}"

mkdir -p "$OUTDIR"

# Derive pcap filename fron config file name + timestamp
BASENAME=$(basename "$CFG")
EXT="${BASENAME##*.}"
NAME="${BASENAME%.*}"

if [ "$EXT" = "ovpn" ]; then
  TYPE="opvn"
elif [ "$EXT" = "conf" ]; then
  TYPE="wg"
else
  TYPE="$EXT"
fi


TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/traffic-${NAME}-${TYPE}-${TIMESTAMP}.pcap"


# Start tcpdump once (capture all traffic)
echo "Starting tcpdump -> $PCAP"
tcpdump -i any -s 0 -w "$PCAP" -U &>/dev/null &
TCPDUMP_PID=$!
trap 'kill $TCPDUMP_PID 2>/dev/null || true' EXIT


# Wait for VPN tunnel to appear
echo "Waiting for VPN $IFACE to come up..."
while ! ip addr show $IFACE &>/dev/null; do
  sleep 1
done
echo "VPN tunnel is up."
sleep 10
# =============================
# IPv6 Leak Test (optional)
# =============================
echo "[agent] === IPv6 Leak Test ==="
ip -6 addr show | grep -v "fe80" || echo "[agent] No non-link-local IPv6 addresses found"

# =============================
# IPv4 / IPv6 URL Tests
# =============================
if [ -f "$URL_FILE" ]; then
  echo "Starting IPv4/IPv6 tests from $URL_FILE"
  while IFS= read -r url || [ -n "$url" ]; do
    url="$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$url" ] && continue
    [[ $url == \#* ]] && continue

    echo "Visiting (IPv4): $url"
    curl -4 -s -L --max-time 30 "$url" >/dev/null || echo "curl IPv4 failed for $url"

    echo "Visiting (IPv6): $url"
    curl -6 -s -L --max-time 30 "$url" >/dev/null || echo "curl IPv6 failed for $url"

    sleep 1
  done < "$URL_FILE"
else
  echo "No URL file found at $URL_FILE"
fi

# =============================
# WebRTC Tests
# =============================
if [ -f "$WEBRTC_FILE" ]; then
  echo "Starting WebRTC tests from $WEBRTC_FILE"

  # JSON file named like pcap but for WebRTC candidates
  WEBRTC_JSON="$OUTDIR/webrtc_candidates-${NAME}-${TYPE}-${TIMESTAMP}.json"
  echo "[]" > "$WEBRTC_JSON"

  while IFS= read -r wurl || [ -n "$wurl" ]; do
    wurl="$(echo "$wurl" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$wurl" ] && continue
    [[ $wurl == \#* ]] && continue

    echo "Running WebRTC probe for $wurl"
    cd /agent
    # Run the probe and append to the single JSON
    if ! timeout 30s node webrtc_check.js "$wurl" "$WEBRTC_JSON"; then
      echo "  -> WebRTC probe timed out or failed for $wurl"
    fi
    sleep 1
  done < "$WEBRTC_FILE"

  echo "WebRTC candidates for this run written to $WEBRTC_JSON"
fi
# =============================
# QUIC / HTTP3 Tests
# =============================
if [ -f "$QUIC_FILE" ]; then
  echo "Starting QUIC/HTTP3 tests from $QUIC_FILE"
  while IFS= read -r qurl || [ -n "$qurl" ]; do
    qurl="$(echo "$qurl" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -z "$qurl" ] && continue
    [[ $qurl == \#* ]] && continue

    echo "Visiting (QUIC/HTTP3): $qurl"
    if ! timeout 30s node /agent/quic_check.js "$qurl" 2>&1; then
      echo "  -> QUIC test timed out or failed for $qurl"
    fi
    sleep 1
  done < "$QUIC_FILE"
else
  echo "No QUIC URL file found at $QUIC_FILE"
fi

# Stop tcpdump
echo "Stopping tcpdump"
kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "=== VPN-Agent Network Info ==="
echo "All interfaces:"
ip addr show

echo "Done. Combined pcap: $PCAP"

echo "Running VPN leak parser on captured traffic..."


