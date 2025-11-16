COMPOSE = docker compose -f compose/docker-compose.yaml
PROFILES_DIR = vpn/profiles
PROFILE ?= proton-free-tcp

.PHONY: up down


up:
	@if [ ! -f "$(PROFILES_DIR)/$(PROFILE).env" ]; then \
	  echo "[make] ERROR: profile '$(PROFILE)' not found at $(PROFILES_DIR)/$(PROFILE).env"; \
	  exit 1; \
	fi

	@echo "[make] Using profile: $(PROFILE)"

	@set -a; \
		. "$(PROFILES_DIR)/$(PROFILE).env"; \
		set +a; \
		echo "  VPN_CONFIG=$$VPN_CONFIG"; \
		echo "  VPN_AUTH_FILE=$$VPN_AUTH_FILE"; \
		echo "  VPN_IFACE=$$VPN_IFACE"; \
	$(COMPOSE) up --build

down:
	$(COMPOSE) down
