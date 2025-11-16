import pyshark
import json
import subprocess
import re
import os
import sys

def get_vpn_ip(container_name="vpn-client"):
    """Get the VPN IP (tun0) from the container."""
    try:
        iface = os.getenv("VPN_IFACE", "tun0")  # Default to tun0 if not set
        output = subprocess.check_output(
            f"docker exec {container_name} ip addr show {iface}", shell=True
        ).decode()
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", output)
        return [match.group(1)] if match else []
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

def parse_pcap(file_path, vpn_ips, vpn_dns_ips):
    cap = pyshark.FileCapture(file_path, only_summaries=False)

    dns_leaks = []
    ipv6_leaks = []
    webrtc_leaks = []
    quic_leaks = []

    for packet in cap:
        ip_src = getattr(packet.ip, 'src', None) or getattr(packet.ipv6, 'src', None)
        ip_dst = getattr(packet.ip, 'dst', None) or getattr(packet.ipv6, 'dst', None)

        # DNS leak -- DNS query is sent to a server that is NOT in the VPN DNS list
        if 'DNS' in packet:
            if ip_src and ip_dst not in vpn_dns_ips:
                dns_leaks.append({
                    'query': getattr(packet.dns, 'qry_name', 'N/A'),
                    'dst_ip': ip_dst
                })

        # IP leak -- packet with an IPv6 source outside of the VPN-assigned IPs is a leak of real IPv6.
        if hasattr(packet, 'ipv6'):
            if ip_src and ip_src not in vpn_ips:
                ipv6_leaks.append({'src_ip': ip_src})

        # WebRTC leak -- if mapped_ip isn't a VPN IP, it’s revealing real public IP
        if 'STUN' in packet:
            # mapped_address is public IP returned by the STUN server.
            mapped_ip = getattr(packet.stun, 'mapped_address', None)
            if mapped_ip and mapped_ip not in vpn_ips:
                webrtc_leaks.append({'mapped_ip': mapped_ip})

        # QUIC/HTTP3 leak -- if a UDP packet to port 443 has a src IP not assigned by the VPN, then real IP is being used for QUIC traffic
        if hasattr(packet, 'udp'):
            if int(packet.udp.dstport) == 443:
                if ip_src and ip_src not in vpn_ips:
                    quic_leaks.append({'src_ip': ip_src})

    return {
        'dns_leaks': dns_leaks,
        'ipv6_leaks': ipv6_leaks,
        'webrtc_leaks': webrtc_leaks,
        'quic_leaks': quic_leaks
    }

def summarize_results(results):
    """Return a descriptive summary showing the details of each leak."""
    summary = {}
    summary['DNS Leak'] = results['dns_leaks'] if results['dns_leaks'] else None
    summary['IPv6 Leak'] = results['ipv6_leaks'] if results['ipv6_leaks'] else None
    summary['WebRTC Leak'] = results['webrtc_leaks'] if results['webrtc_leaks'] else None
    summary['QUIC Leak'] = results['quic_leaks'] if results['quic_leaks'] else None
    return summary

def parse_directory(pcap_dir, vpn_ips, vpn_dns_ips):
    summary_dict = {}
    for root, _, files in os.walk(pcap_dir):
        for file in files:
            if file.endswith(".pcap") or file.endswith(".pcapng"):
                pcap_path = os.path.join(root, file)
                results = parse_pcap(pcap_path, vpn_ips, vpn_dns_ips)
                summary_dict[file] = summarize_results(results)
    return summary_dict

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_parser.py <pcap_directory>")
        sys.exit(1)

    pcap_dir = sys.argv[1]
    vpn_ips = get_vpn_ip()
    vpn_dns_ips = get_dns_ips()

    print(f"Detected VPN IP(s): {vpn_ips}")
    print(f"Detected DNS IP(s): {vpn_dns_ips}")

    all_summaries = parse_directory(pcap_dir, vpn_ips, vpn_dns_ips)

    # Save a single JSON with summaries for all pcaps
    output_file = os.path.join("results", "leak_summary.json")
    os.makedirs("results", exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(all_summaries, f, indent=4)

    print(f"\n=== All pcap summaries saved to {output_file} ===")
