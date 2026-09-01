# Thin wrapper around ./cs — host needs only podman (+ make is optional).
COMPOSE = podman compose
PYTHON_IMG = localhost/cybersnare-python:lab

.PHONY: bootstrap up down logs ps rebuild verify events health export import

bootstrap:
	./scripts/bootstrap.sh

up:
	./cs up

down:
	./cs down

rebuild:
	./cs rebuild

ps:
	./cs ps

logs:
	./cs logs

health:
	./cs health

events:
	./cs events

verify:
	./cs verify

export:
	./cs export

import:
	./cs import
