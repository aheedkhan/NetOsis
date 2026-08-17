COMPOSE = podman compose

.PHONY: up down logs ps rebuild verify events health

up:
	systemctl --user start podman.socket
	mkdir -p data/events data/manifests
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down --remove-orphans

rebuild:
	systemctl --user start podman.socket
	mkdir -p data/events data/manifests
	$(COMPOSE) up -d --build --force-recreate

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs --tail=80

health:
	curl -sS http://127.0.0.1:18088/health && echo
	curl -sS http://127.0.0.1:19000/health && echo

events:
	curl -sS http://127.0.0.1:18088/v1/tail?n=20 | python3 -m json.tool

verify:
	./scripts/verify.sh
