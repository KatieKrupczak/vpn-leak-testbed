COMPOSE = docker compose -f compose/docker-compose.yaml

# Default provider if none set
VPN_CONFIG ?= /etc/vpn/configs/default.ovpn

up:
	VPN_CONFIG=$(VPN_CONFIG) $(COMPOSE) up --build

down:
	$(COMPOSE) down
