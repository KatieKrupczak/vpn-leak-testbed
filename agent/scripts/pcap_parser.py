import pyshark
import json
import os
import sys
import ipaddress
import subprocess
import re

# ===============================
# Check if IP is public and not a VPN IP
# ===============================
def is_public_ip(ip, vpn_ips):
    try:
        ip_obj = ipaddress.ip_address(ip)

        # IPv4 private ranges
        if isinstance(ip_obj, ipaddress.IPv4Address):
            private_ranges = [
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
                ipaddress.IPv4Network("127.0.0.0/8")
            ]
            if any(ip_obj in net for net in private_ranges):
                return False

        # IPv6 private / link-local
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.is_private or ip_obj.is_link_local:
                return False

        # Loopback
        if ip_obj.is_loopback:
            return False

        # VPN IP exclusion
        if ip in vpn_ips:
            return False

        return True
    except ValueError:
        return False
# ===============================
# Get public IP via curl inside container (Script 1)
# ===============================
def get_vpn_public_ip(container_name="vpn-client"):
    try:
        output = subprocess.check_output(
            f"docker exec {container_name} curl -s https://ifconfig.me",
            shell=True
        ).decode().strip()
        return [output] if output else []
    except subprocess.CalledProcessError:
        return []

# ===============================
# WebRTC JSON leak parser (Script 1 logic)
# ===============================
def parse_webrtc_file(webrtc_json_path, vpn_ips):
    leaks = []
    if not webrtc_json_path or not os.path.isfile(webrtc_json_path):
        return leaks
    try:
        with open(webrtc_json_path) as f:
            data = json.load(f)
    except Exception:
        return leaks

    for entry in data:
        url = entry.get("url")
        candidates = entry.get("candidates", [])
        for c in candidates:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\d+\s+typ', c)
            if match:
                ip = match.group(1)
                if ip not in vpn_ips and is_public_ip(ip):
                    leaks.append({'mapped_ip': ip, 'url': url, 'candidate': c})
    return leaks

# ===============================
# Parse a single pcap file
# ===============================
def parse_pcap(pcap_path, vpn_ips, vpn_dns_ips, ipv6_ok=True, webrtc_json_path=None):
    dns_leaks = []
    ipv4_leaks = []
    ipv6_leaks = []
    webrtc_leaks = []
    quic_leaks = []
    logs = []

    seen_dns = set()
    seen_ipv4 = set()
    seen_ipv6 = set()
    seen_webrtc = set()
    seen_quic = set()

    # Pre-parse WebRTC JSON (Script 1 logic)
    json_webrtc_leaks = parse_webrtc_file(webrtc_json_path, vpn_ips) if webrtc_json_path else []

    print(f"[INFO] Parsing {pcap_path}")
    try:
        cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    except Exception as e:
        print(f"[ERROR] Could not read {pcap_path}: {e}")
        return {}

    for pkt in cap:
        try:
            ip_src = getattr(pkt.ip, "src", None) if hasattr(pkt, "ip") else None
            ip_dst = getattr(pkt.ip, "dst", None) if hasattr(pkt, "ip") else None
            ipv6_src = getattr(pkt.ipv6, "src", None) if hasattr(pkt, "ipv6") else None
            ipv6_dst = getattr(pkt.ipv6, "dst", None) if hasattr(pkt, "ipv6") else None

            src = ip_src or ipv6_src
            dst = ip_dst or ipv6_dst

            logs.append(f"[PKT] src={src}, dst={dst}, layers={[l.layer_name for l in pkt.layers]}")

            # DNS leak
            if hasattr(pkt, "dns"):
                qry = getattr(pkt.dns, "qry_name", "N/A")
                if dst and is_public_ip(dst, vpn_dns_ips) and dst not in seen_dns:
                    dns_leaks.append({"query": qry, "dst_ip": dst, "reason": "public DNS outside VPN"})
                    logs.append(f"[DNS LEAK] Query={qry}, dst={dst}")
                    seen_dns.add(dst)

            # IPv4 leak
            if ip_src and ipaddress.ip_address(ip_src).version == 4:
                if is_public_ip(ip_src, vpn_ips) and ip_src not in seen_ipv4:
                    ipv4_leaks.append({"src_ip": ip_src, "reason": "public IPv4 outside VPN"})
                    logs.append(f"[IPv4 LEAK] src={ip_src}")
                    seen_ipv4.add(ip_src)

            # IPv6 leak
            if ipv6_src and ipaddress.ip_address(ipv6_src).version == 6:
                if ipv6_ok and is_public_ip(ipv6_src, vpn_ips) and ipv6_src not in seen_ipv6:
                    ipv6_leaks.append({"src_ip": ipv6_src, "reason": "public IPv6 outside VPN"})
                    logs.append(f"[IPv6 LEAK] src={ipv6_src}")
                    seen_ipv6.add(ipv6_src)

            # QUIC leak
            if hasattr(pkt, "udp") and getattr(pkt.udp, "dstport", "") == "443":
                if src and is_public_ip(src, vpn_ips) and src not in seen_quic:
                    quic_leaks.append({"src_ip": src, "reason": "QUIC public IP leak"})
                    logs.append(f"[QUIC LEAK] src={src}")
                    seen_quic.add(src)

        except Exception as e:
            logs.append(f"[ERROR parsing packet] {e}")
            continue

    cap.close()

    # Add WebRTC leaks (Script 1 logic)
    for j in json_webrtc_leaks:
        ip = j.get("mapped_ip")
        if ip and ip not in seen_webrtc:
            webrtc_leaks.append(j)
            seen_webrtc.add(ip)

    return {
        "dns_leaks": dns_leaks,
        "ipv4_leaks": ipv4_leaks,
        "ipv6_leaks": ipv6_leaks,
        "webrtc_leaks": webrtc_leaks,
        "quic_leaks": quic_leaks,
        "logs": logs,
    }

# ===============================
# Summarize results for JSON output
# ===============================
def summarize(results):
    return {
        "DNS Leak": results["dns_leaks"] or None,
        "IPv4 Leak": results["ipv4_leaks"] or None,
        "IPv6 Leak": results["ipv6_leaks"] or None,
        "WebRTC Leak": results["webrtc_leaks"] or None,
        "QUIC Leak": results["quic_leaks"] or None,
        "debug_log": results["logs"],
    }

# ===============================
# Parse directory or single file
# ===============================
def parse_input(path, vpn_ips, vpn_dns_ips, ipv6_ok, webrtc_json_path):
    if os.path.isfile(path):
        res = parse_pcap(path, vpn_ips, vpn_dns_ips, ipv6_ok, webrtc_json_path)
        return {os.path.basename(path): summarize(res)}

    elif os.path.isdir(path):
        summaries = {}
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith(".pcap") or f.endswith(".pcapng"):
                    full = os.path.join(root, f)
                    res = parse_pcap(full, vpn_ips, vpn_dns_ips, ipv6_ok, webrtc_json_path)
                    summaries[f] = summarize(res)
        return summaries

    else:
        print(f"[ERROR] {path} is not a valid file or directory")
        return {}

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python3 pcap_parser.py <pcap_file_or_dir> <vpn_ipv4> <vpn_ipv6> <vpn_dns> <ipv6_ok> <webrtc_json_or_none>")
        sys.exit(1)

    path = sys.argv[1]
    vpn_ipv4_list = sys.argv[2].split(",")
    vpn_ipv6_list = sys.argv[3].split(",")
    vpn_dns_list = sys.argv[4].split(",")
    ipv6_ok = sys.argv[5].lower() in ["true", "1", "yes"]
    webrtc_json_path = sys.argv[6] if sys.argv[6].lower() != "none" else None

    vpn_ips = vpn_ipv4_list + vpn_ipv6_list
    vpn_dns_ips = vpn_dns_list

    # Add public IP via curl (Script 1 logic)
    public_ips = get_vpn_public_ip()
    if public_ips:
        print(f"[INFO] Adding public VPN IP from curl: {public_ips}")
        vpn_ips.extend(public_ips)

    summaries = parse_input(path, vpn_ips, vpn_dns_ips, ipv6_ok, webrtc_json_path)

    os.makedirs("results", exist_ok=True)
    outfile = "results/leak_summary.json"
    with open(outfile, "w") as f:
        json.dump(summaries, f, indent=4)

    print(f"[DONE] Results saved → {outfile}")
