#!/usr/bin/env python3
import pyshark
import json
import subprocess
import re
import os
import sys

# ----------------------
# Helper functions
# ----------------------
def get_vpn_ip(container_name="vpn-client"):
    """Get the VPN tunnel IPs (tun0) from the container (IPv4 + IPv6)."""
    iface = os.getenv("VPN_IFACE", "tun0")
    try:
        output = subprocess.check_output(
            f"docker exec {container_name} ip addr show {iface}", shell=True
        ).decode()
        ips = []

        # IPv4
        for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", output):
            ips.append(match.group(1))
        # IPv6
        for match in re.finditer(r"inet6 ([0-9a-f:]+)", output):
            ips.append(match.group(1))
        return ips
    except subprocess.CalledProcessError:
        return []

def get_vpn_public_ip(container_name="vpn-client"):
    """Get the VPN public IP as seen from the container."""
    try:
        output = subprocess.check_output(
            f"docker exec {container_name} curl -s https://ifconfig.me", shell=True
        ).decode().strip()
        return [output] if output else []
    except subprocess.CalledProcessError:
        return []

def get_dns_ips(container_name="vpn-client"):
    """Get DNS IPs from the container."""
    try:
        output = subprocess.check_output(
            f"docker exec {container_name} cat /etc/resolv.conf", shell=True
        ).decode()
        dns_ips = []
        for line in output.splitlines():
            if line.startswith("nameserver"):
                dns_ips.append(line.split()[1])
        return dns_ips
    except subprocess.CalledProcessError:
        return []

# ----------------------
# Parsing logic
# ----------------------
def parse_pcap(file_path, vpn_ips, vpn_dns_ips, webrtc_json_path=None):
    cap = pyshark.FileCapture(file_path, only_summaries=False)

    dns_leaks = []
    ipv6_leaks = []
    quic_leaks = []
    webrtc_leaks = []

    for packet in cap:
        ip_src = getattr(packet.ip, 'src', None) or getattr(packet.ipv6, 'src', None)
        ip_dst = getattr(packet.ip, 'dst', None) or getattr(packet.ipv6, 'dst', None)

        # DNS leak
        if 'DNS' in packet:
            if ip_src and ip_dst not in vpn_dns_ips:
                dns_leaks.append({'query': getattr(packet.dns, 'qry_name', 'N/A'), 'dst_ip': ip_dst})

        # IPv6 leak
        if hasattr(packet, 'ipv6') and ip_src:
            if ip_src not in vpn_ips:
                ipv6_leaks.append({'src_ip': ip_src})

        # QUIC leak (UDP 443)
        if hasattr(packet, 'udp') and ip_src:
            if int(packet.udp.dstport) == 443:
                if ip_src not in vpn_ips:
                    quic_leaks.append({'src_ip': ip_src})

    # ----------------------
    # WebRTC leaks from JSON file
    # ----------------------
    if webrtc_json_path and os.path.isfile(webrtc_json_path):
        with open(webrtc_json_path) as f:
            webrtc_data = json.load(f)

        for entry in webrtc_data:
            url = entry.get("url")
            candidates = entry.get("candidates", [])
            for c in candidates:
                # Extract candidate IP
                match = re.search(r'\s(\d+\.\d+\.\d+\.\d+|\S+):?\d*\s', c)
                if match:
                    ip = match.group(1)
                    if ip not in vpn_ips:
                        webrtc_leaks.append({'mapped_ip': ip, 'url': url, 'candidate': c})

    return {
        'dns_leaks': dns_leaks,
        'ipv6_leaks': ipv6_leaks,
        'quic_leaks': quic_leaks,
        'webrtc_leaks': webrtc_leaks
    }

def summarize_results(results, vpn_ips, vpn_dns_ips):
    return {
        'detected_vpn_ips': vpn_ips,
        'detected_dns_ips': vpn_dns_ips,
        'DNS Leak': results['dns_leaks'] if results['dns_leaks'] else None,
        'IPv6 Leak': results['ipv6_leaks'] if results['ipv6_leaks'] else None,
        'QUIC Leak': results['quic_leaks'] if results['quic_leaks'] else None,
        'WebRTC Leak': results['webrtc_leaks'] if results['webrtc_leaks'] else None
    }

def parse_directory(pcap_dir, vpn_ips, vpn_dns_ips, webrtc_json_path=None):
    summary_dict = {}
    for root, _, files in os.walk(pcap_dir):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                pcap_path = os.path.join(root, file)
                results = parse_pcap(pcap_path, vpn_ips, vpn_dns_ips, webrtc_json_path)
                summary_dict[file] = summarize_results(results, vpn_ips, vpn_dns_ips)
    return summary_dict

# ----------------------
# Main
# ----------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_parser.py <pcap_directory> [webrtc_json_file]")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    webrtc_json_path = sys.argv[2] if len(sys.argv) > 2 else None

    vpn_ips = get_vpn_ip() + get_vpn_public_ip()
    vpn_dns_ips = get_dns_ips()

    print(f"Detected VPN IP(s): {vpn_ips}")
    print(f"Detected DNS IP(s): {vpn_dns_ips}")

    # Load existing summary JSON if it exists
    output_file = os.path.join("results", "leak_summary.json")
    os.makedirs("results", exist_ok=True)
    if os.path.isfile(output_file):
        with open(output_file) as f:
            all_summaries = json.load(f)
    else:
        all_summaries = {}

    # Parse new PCAPs and append
    new_summaries = parse_directory(pcap_dir, vpn_ips, vpn_dns_ips, webrtc_json_path)
    all_summaries.update(new_summaries)

    # Write back the combined JSON
    with open(output_file, 'w') as f:
        json.dump(all_summaries, f, indent=4)

    print(f"\n=== All pcap summaries saved to {output_file} ===")
