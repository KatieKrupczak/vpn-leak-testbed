# vpn-leak-testbed
A containerized testbed for evaluating VPN privacy leaks across IPv6, DNS, and WebRTC. Includes automated tools to detect traffic escaping the VPN tunnel, analyze encrypted DNS and QUIC behavior, and reproduce results across VPN providers.

# To start containers
```
VPN_CONFIG=/etc/vpn/configs/proton-free-tcp.ovpn \
VPN_AUTH_FILE=/etc/vpn/auth/proton-auth.txt \
make up
```