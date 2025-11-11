#!/usr/bin/env bash
set -euo pipefail

URL_FILE="/tests/urls.txt"
OUTDIR="/results"
mkdir -p "$OUTDIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
PCAP="$OUTDIR/traffic-$TIMESTAMP.pcap"

echo "Starting tcpdump -> $PCAP"
tcpdump -i any -s 0 -w "$PCAP" -U &>/dev/null &
TCPDUMP_PID=$!

trap "kill $TCPDUMP_PID 2>/dev/null || true" EXIT

sleep 1  # give tcpdump a moment to start

echo "Visiting URLs from $URL_FILE"
while IFS= read -r url || [ -n "$url" ]; do
    # trim whitespace and skip empty/comment lines
    url=$(echo "$url" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$url" ] && continue
    [[ $url == \#* ]] && continue

    echo "Visiting: $url"
    curl -s -L --max-time 30 "$url" >/dev/null || echo "curl failed for $url"
    sleep 1
done < "$URL_FILE"

echo "Stopping tcpdump"
kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "Done. Combined pcap: $PCAP"
