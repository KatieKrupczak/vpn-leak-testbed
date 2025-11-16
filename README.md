# vpn-leak-testbed
A containerized testbed for evaluating VPN privacy leaks across IPv6, DNS, and WebRTC. Includes automated tools to detect traffic escaping the VPN tunnel, analyze encrypted DNS and QUIC behavior, and reproduce results across VPN providers.

# Double Check IPv6 enabled in Docker
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

# To start containers
```
make up PROFILE=<vpn profile name>

# e.g. make up PROFILE=proton-free-tcp
```

VPN_CONFIG=/etc/vpn/configs/protonplus.conf \
VPN_AUTH_FILE= \
VPN_IFACE=protonplus \
make up