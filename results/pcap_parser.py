import pyshark # need to install tshark in container this script is ran in 
import json
import sys

def parse_pcap(file_path, vpn_ips, vpn_dns_ips):
    cap = pyshark.FileCapture(file_path, only_summaries=False)

    dns_leaks = []
    ipv6_leaks = []
    webrtc_leaks = []
    quic_leaks = []

    for packet in cap:
        ip_src = getattr(packet.ip, 'src', None) or getattr(packet.ipv6, 'src', None)
        ip_dst = getattr(packet.ip, 'dst', None) or getattr(packet.ipv6, 'dst', None)

        # DNS leak -- if not in vpn_dns_ips, then its using another DNS (leak)
        if 'DNS' in packet:
            if ip_src and ip_dst not in vpn_dns_ips:
                dns_leaks.append({
                    'query': getattr(packet.dns, 'qry_name', 'N/A'),
                    'dst_ip': ip_dst
                })
        
        #IPv6 leak -- if src IPv6 address is not a VPN IP, it’s leaking the real IPv6
        if hasattr(packet, 'ipv6'):
            if ip_src and ip_src not in vpn_ips:
                ipv6_leaks.append({
                    'src_ip': ip_src
                })

        #WebRTC leak -- if STUN server IP is not in VPN IPs, it’s leaking real IP
        if 'STUN' in packet:
            mapped_ip = getattr(packet.stun, 'mapped_address', None)
            if mapped_ip and mapped_ip not in vpn_ips:
                webrtc_leaks.append({
                    'mapped_ip': mapped_ip
                })

        if hasattr(packet, 'udp'):
            if int(packet.udp.dstport) == 443:
                if (ip_src and ip_src not in vpn_ips):
                    quic_leaks.append({
                        'src_ip': ip_src
                })
                    
    return {
        'dns_leaks': dns_leaks,
        'ipv6_leaks': ipv6_leaks,
        'webrtc_leaks': webrtc_leaks,
        'quic_leaks': quic_leaks
    }

def display_results(results):
    results = {}
    results['DNS Leak'] = bool(results['dns_leaks'])
    results['IPv6 Leak'] = bool(results['ipv6_leaks'])
    results['WebRTC Leak'] = bool(results['webrtc_leaks'])
    results['QUIC Leak'] = bool(results['quic_leaks'])
    return results

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python pcap_parser.py <pcap_file> <vpn_ip1,vpn_ip2,...> <vpn_dns1,vpn_dns2,...>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    vpn_ips = sys.argv[2].split(',')
    vpn_dns_ips = sys.argv[3].split(',')

    results = parse_pcap(pcap_file, vpn_ips, vpn_dns_ips)
    summary = display_results(results)

    print("\n=== Leak Summary ===")
    for k, v in summary.items():
        print(f"{k}: {'YES' if v else 'NO'}")

    with open('results/leak_report.json', 'w') as f:
        json.dump(results, f, indent=4)

