#!/bin/bash
# ===============================
# PCAP Leak Parser Runner Template
# ===============================

# Path to PCAP file or directory
PCAP_PATH="./pcaps"   # e.g., ./pcaps/session1.pcap or ./pcaps/

# VPN IPs
VPN_IPV4="10.8.0.2,10.8.0.3"
VPN_IPV6="fd42:abcd:1234::2,fd42:abcd:1234::3"   # Use "none" if you have no IPv6
VPN_DNS="10.8.0.1,8.8.8.8"

# Enable IPv6 leak checking? (true/false)
IPV6_OK="true"

# WebRTC JSON file (leave "none" if not used)
WEBRTC_JSON="./webrtc_leaks.json"

# Private IPs
PRIVATE_IPV4="192.168.1.100"       # Mandatory
PRIVATE_IPV6="fd42:abcd:1234::100" # Optional, use "none" to skip

# Endpoint IP that private IPs are allowed to communicate with
ENDPOINT_IP="203.0.113.5"

# ===============================
# Run the parser
# ===============================
python3 pcap_parser.py \
    "$PCAP_PATH" \
    "$VPN_IPV4" \
    "$VPN_IPV6" \
    "$VPN_DNS" \
    "$IPV6_OK" \
    "$WEBRTC_JSON" \
    "$PRIVATE_IPV4" \
    "$PRIVATE_IPV6" \
    "$ENDPOINT_IP"
