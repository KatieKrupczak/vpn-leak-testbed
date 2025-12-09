#!/bin/bash
# ===============================
# PCAP Leak Parser Runner Template
# ===============================

# Path to PCAP file or directory
PCAP_PATH="../../results/traffic-express-basic-udp-opvn-20251209-182013.pcap"   # e.g., ./pcaps/session1.pcap or ./pcaps/

# VPN IPs
VPN_IPV4="10.61.0.87"
VPN_IPV6="fe80::6f08:61d4:3c7e:9c5f"   # Use "none" if you have no IPv6
VPN_DNS="10.61.0.1"

# Enable IPv6 leak checking? (true/false)
IPV6_OK="true"

# WebRTC JSON file (leave "none" if not used)
WEBRTC_JSON="../../results/webrtc_candidates-express-basic-udp-opvn-20251209-182013.json"

# Private IPs
PRIVATE_IPV4="172.19.0.2"       # Mandatory
PRIVATE_IPV6="none" # Optional, use "none" to skip

# Endpoint IP that private IPs are allowed to communicate with
ENDPOINT_IP="45.80.157.190"

# ===============================
# Run the parser
# ===============================
python pcap_parser.py \
    "$PCAP_PATH" \
    "$VPN_IPV4" \
    "$VPN_IPV6" \
    "$VPN_DNS" \
    "$IPV6_OK" \
    "$WEBRTC_JSON" \
    "$PRIVATE_IPV4" \
    "$PRIVATE_IPV6" \
    "$ENDPOINT_IP"
