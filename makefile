PROFILE ?= proton-free-tcp

COMPOSE_FILE = compose/docker-compose.yaml
ENV_FILE = vpn/profiles/$(PROFILE).env

up:
	docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE) up --build

down:
	docker compose -f $(COMPOSE_FILE) --env-file $(ENV_FILE) down -v
