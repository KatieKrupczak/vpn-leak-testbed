#!/usr/bin/env python3
import pyshark
import json
import subprocess
import re
import os
import sys
from ipaddress import ip_address, IPv4Address, IPv6Address, IPv4Network, IPv6Network

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

def is_private_ip(ip):
    """Check if IP is a private/tunnel/local address (IPv4/IPv6)."""
    try:
        ip_obj = ip_address(ip)
        if isinstance(ip_obj, IPv4Address):
            private_ranges = [
                IPv4Network("10.0.0.0/8"),
                IPv4Network("172.16.0.0/12"),
                IPv4Network("192.168.0.0/16"),
                IPv4Network("127.0.0.0/8")
            ]
            return any(ip_obj in net for net in private_ranges)
        elif isinstance(ip_obj, IPv6Address):
            return ip_obj.is_link_local or ip_obj.is_private
    except ValueError:
        return False
    return False

# ----------------------
# Parsing logic
# ----------------------
def parse_pcap(file_path, vpn_ips, vpn_dns_ips, webrtc_json_path=None):
    cap = pyshark.FileCapture(file_path, only_summaries=False)

    dns_leaks = []
    ipv6_leaks = []
    webrtc_leaks = []
    quic_leaks = []

    packet_count = 0
    for packet in cap:
        packet_count += 1
        if packet_count % 1000 == 0:
            print(f"Processed {packet_count} packets...")
        if hasattr(packet, "ip"):
            ip_src = getattr(packet.ip, "src", None)
            ip_dst = getattr(packet.ip, "dst", None)
        elif hasattr(packet, "ipv6"):
            ip_src = getattr(packet.ipv6, "src", None)
            ip_dst = getattr(packet.ipv6, "dst", None)
        else:
            ip_src = None
            ip_dst = None

        # DNS leak - detect DNS queries NOT going to VPN DNS servers
        if 'DNS' in packet:
            if ip_dst and ip_dst not in vpn_dns_ips and not is_private_ip(ip_dst):
                dns_leaks.append({
                    'query': getattr(packet.dns, 'qry_name', 'N/A'),
                    'dst_ip': ip_dst
                })

        # IPv6 leak
        if hasattr(packet, 'ipv6') and ip_src:
            if ip_src not in vpn_ips and not is_private_ip(ip_src):
                ipv6_leaks.append({'src_ip': ip_src})

        # QUIC leak (UDP 443)
        if hasattr(packet, 'udp') and ip_src:
            if int(packet.udp.dstport) == 443:
                if ip_src not in vpn_ips and not is_private_ip(ip_src):
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
                # Extract candidate IP - look for IPv4 after "typ srflx" or actual IP addresses
                # Format: "candidate:... <ip> <port> typ ..."
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+typ', c)
                if match:
                    ip = match.group(1)
                    if ip not in vpn_ips and not is_private_ip(ip):
                        webrtc_leaks.append({'mapped_ip': ip, 'url': url, 'candidate': c})

    cap.close()
    print(f"Total packets processed: {packet_count}")
    
    return {
        'dns_leaks': dns_leaks,
        'ipv6_leaks': ipv6_leaks,
        'webrtc_leaks': webrtc_leaks,
        'quic_leaks': quic_leaks
    }

def summarize_results(results, vpn_ips, vpn_dns_ips):
    summary = {}
    summary['VPN IPs'] = vpn_ips
    summary['DNS IPs'] = vpn_dns_ips
    summary['DNS Leak'] = results['dns_leaks'] if results['dns_leaks'] else None
    summary['IPv6 Leak'] = results['ipv6_leaks'] if results['ipv6_leaks'] else None
    summary['WebRTC Leak'] = results['webrtc_leaks'] if results['webrtc_leaks'] else None
    summary['QUIC Leak'] = results['quic_leaks'] if results['quic_leaks'] else None
    return summary

# ----------------------
# Main
# ----------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_parser.py <pcap_filename> [webrtc_json_filename]")
        sys.exit(1)

    # Get script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Setup paths
    results_dir = os.path.join(script_dir, "..", "..", "results")
    output_dir = os.path.join(script_dir, "results")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get input files
    pcap_filename = sys.argv[1]
    pcap_file = os.path.join(results_dir, pcap_filename)
    
    webrtc_json_path = None
    if len(sys.argv) > 2:
        webrtc_filename = sys.argv[2]
        webrtc_json_path = os.path.join(results_dir, webrtc_filename)

    # Validate files exist
    if not os.path.isfile(pcap_file):
        print(f"Error: PCAP file not found: {pcap_file}")
        sys.exit(1)
    
    if webrtc_json_path and not os.path.isfile(webrtc_json_path):
        print(f"Error: WebRTC JSON file not found: {webrtc_json_path}")
        sys.exit(1)

    # VPN info
    vpn_ips = get_vpn_ip() + get_vpn_public_ip()
    vpn_dns_ips = get_dns_ips()

    print(f"Detected VPN IP(s): {vpn_ips}")
    print(f"Detected DNS IP(s): {vpn_dns_ips}")

    # Parse the pcap file
    print(f"\nParsing {pcap_file}...")
    results = parse_pcap(pcap_file, vpn_ips, vpn_dns_ips, webrtc_json_path)
    
    filename = os.path.basename(pcap_file)
    summary = {filename: summarize_results(results, vpn_ips, vpn_dns_ips)}

    # Write output file to agent/scripts/results/
    output_json = os.path.join(output_dir, f"{os.path.splitext(pcap_filename)[0]}_summary.json")
    with open(output_json, "w") as f:
        json.dump(summary, f, indent=4)

    print(f"\n=== Summary written to: {output_json} ===")