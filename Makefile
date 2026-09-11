.PHONY: test compose-config up down logs

test:
	PYTHONPATH=. python3 -W error -m unittest discover -v

compose-config:
	docker compose config --quiet

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs --no-color --tail=100
