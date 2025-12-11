# VPN Privacy Leaks: A 2025 Reality Check — Testbed
*A containerized measurement framework for evaluating VPN privacy leaks across IPv4, IPv6, DNS, WebRTC, and QUIC.*

This repository contains the full implementation of the experimental testbed used in VPN Privacy Leaks: A 2025 Reality Check. The system automates VPN tunnel setup, traffic generation, packet capture, and leak analysis to determine whether identifying information escapes commercial VPN tunnels under modern network conditions.

The framework supports **OpenVPN** and **WireGuard** configurations and is designed to be reproducible, provider-agnostic, and easy to extend for additional experiments.

**NOTE:** Provider `.ovpn` and `.conf` configurations and auth files not provided

## Features
- Automated testing of:
  - **IPv4 routing**
  - **IPv6 routing & leak detection**
  - **DNS resolution paths**
  - **WebRTC ICE candidate exposure**
  - **QUIC / HTTP/3 traffic routing**
- Reproducible Docker-based testbed  
- Packet capture via tcpdump + offline Python leak analysis  
- Chromium-based WebRTC + QUIC probing (mDNS-aware)

## Architecture
The testbed uses two cooperating Docker containers:

- **`vpn-client`**  
  Establishes the VPN tunnel (OpenVPN or WireGuard) and exposes `tun0`/`wg0`.

- **`vpn-agent`**  
  Generates IPv4/IPv6/DNS/QUIC/WebRTC traffic and captures all packets for analysis.

All results are stored under: `/results`

## 🛠️ System Requirements
- Host with Docker ≥ 20.10  
- Support for `/dev/net/tun` inside containers  
- IPv6 enabled in Docker (required for IPv6 leak testing)

### Double Check IPv6 enabled in Docker
```
cat /etc/docker/daemon.json
```
Should return something like:
```
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:dead:beef::/64"
}
```
If not follow these steps:
1. Create `/etc/docker/daemon.json`
    ```
    sudo nano /etc/docker/daemon.json
    ```
    Put this in
    ```
    {
      "ipv6": true,
      "fixed-cidr-v6": "fd00:dead:beef::/64"
    }
    ```

2. Restart Docker
   ```
   sudo systemctl restart docker
   ```
3. Check that its happy
   ```
   sudo systemctl status docker
   ```

## Running the Testbed
Each VPN configuration is defined as a PROFILE containing paths to config and auth file and interface name tun0/wg0
```
make up PROFILE=<vpn profile name>

# e.g. make up PROFILE=proton-free-tcp
```

The system will:
1. Start the VPN client
2. Wait for tunnel initialization
3. Begin packet capture
4. Run IPv4/IPv6/DNS/QUIC/WebRTC probes
5. Save output artifacts under results/
