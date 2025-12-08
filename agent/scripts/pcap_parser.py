import pyshark
import json
import os
import sys
import ipaddress

# ===============================
# Helper: Check if IP is public and not a VPN IP
# ===============================
def is_public_ip(ip, vpn_ips):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
        if ip in vpn_ips:
            return False
        return True
    except ValueError:
        return False

# ===============================
# Parse a single pcap file
# ===============================
def parse_pcap(pcap_path, vpn_ips, vpn_dns_ips, ipv6_ok=True):
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
                    logs.append(f"[DNS LEAK] Query={qry}, dst={dst}, reason=public DNS outside VPN")
                    seen_dns.add(dst)

            # IPv4 leak
            if ip_src and ipaddress.ip_address(ip_src).version == 4:
                if is_public_ip(ip_src, vpn_ips) and ip_src not in seen_ipv4:
                    ipv4_leaks.append({"src_ip": ip_src, "reason": "public IPv4 outside VPN"})
                    logs.append(f"[IPv4 LEAK] src={ip_src}, reason=public IPv4 outside VPN")
                    seen_ipv4.add(ip_src)

            # IPv6 leak
            if ipv6_src and ipaddress.ip_address(ipv6_src).version == 6:
                if ipv6_ok and is_public_ip(ipv6_src, vpn_ips) and ipv6_src not in seen_ipv6:
                    ipv6_leaks.append({"src_ip": ipv6_src, "reason": "public IPv6 outside VPN"})
                    logs.append(f"[IPv6 LEAK] src={ipv6_src}, reason=public IPv6 outside VPN")
                    seen_ipv6.add(ipv6_src)

            # WebRTC STUN leak
            if hasattr(pkt, "stun"):
                mapped_ip = getattr(pkt.stun, "mapped_address", None)
                if mapped_ip and is_public_ip(mapped_ip, vpn_ips) and mapped_ip not in seen_webrtc:
                    webrtc_leaks.append({"mapped_ip": mapped_ip, "reason": "WebRTC public IP leak"})
                    logs.append(f"[WEBRTC LEAK] mapped={mapped_ip}, reason=WebRTC public IP leak")
                    seen_webrtc.add(mapped_ip)

            # QUIC leak (UDP/443)
            if hasattr(pkt, "udp"):
                if getattr(pkt.udp, "dstport", "") == "443":
                    if src and is_public_ip(src, vpn_ips) and src not in seen_quic:
                        quic_leaks.append({"src_ip": src, "reason": "QUIC public IP leak"})
                        logs.append(f"[QUIC LEAK] src={src}, reason=QUIC public IP leak")
                        seen_quic.add(src)

        except Exception as e:
            logs.append(f"[ERROR parsing packet] {e}")
            continue

    cap.close()

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
def parse_input(path, vpn_ips, vpn_dns_ips, ipv6_ok):
    if os.path.isfile(path):
        res = parse_pcap(path, vpn_ips, vpn_dns_ips, ipv6_ok)
        return {os.path.basename(path): summarize(res)}
    elif os.path.isdir(path):
        summaries = {}
        for root, _, files in os.walk(path):
            for f in files:
                if f.endswith(".pcap") or f.endswith(".pcapng"):
                    full = os.path.join(root, f)
                    res = parse_pcap(full, vpn_ips, vpn_dns_ips, ipv6_ok)
                    summaries[f] = summarize(res)
        return summaries
    else:
        print(f"[ERROR] {path} is not a valid file or directory")
        return {}

# ===============================
# Main
# ===============================
if __name__ == "__main__":
    if len(sys.argv) != 6:
        print("Usage: python3 pcap_parser.py <pcap_file_or_dir> <comma-separated-vpn-IPv4> <comma-separated-vpn-IPv6> <comma-separated-vpn-DNS> <ipv6_ok>")
        sys.exit(1)

    path = sys.argv[1]
    vpn_ipv4_list = sys.argv[2].split(",")
    vpn_ipv6_list = sys.argv[3].split(",")
    vpn_dns_list = sys.argv[4].split(",")
    ipv6_ok = sys.argv[5].lower() in ["true", "1", "yes"]

    vpn_ips = vpn_ipv4_list + vpn_ipv6_list
    vpn_dns_ips = vpn_dns_list

    summaries = parse_input(path, vpn_ips, vpn_dns_ips, ipv6_ok)

    os.makedirs("results", exist_ok=True)
    outfile = "results/leak_summary.json"
    with open(outfile, "w") as f:
        json.dump(summaries, f, indent=4)

    print(f"[DONE] Results saved → {outfile}")
