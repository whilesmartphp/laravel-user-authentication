.PHONY: help up down install test pint pint-test lint build serve clean prepare restart logs shell

help:
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@egrep '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart

logs:
	docker compose logs -f

shell:
	docker compose exec app bash

install: up
	docker compose exec app composer install

test:
	docker compose exec app ./vendor/bin/testbench package:test

pint:
	docker compose exec app composer pint

pint-test:
	docker compose exec app composer pint:test

lint: pint

build:
	docker compose exec app composer build

serve:
	docker compose exec app composer serve

clean:
	docker compose exec app composer clear

prepare:
	docker compose exec app composer prepare

autoload:
	docker compose exec app composer dump-autoload

fresh: down up install
	@echo "Environment is ready!"

setup: fresh test
	@echo "Setup complete!"

check: pint-test test
	@echo "All checks passed!"
