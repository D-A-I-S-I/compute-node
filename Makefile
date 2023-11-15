run:
	docker compose run --remove-orphans --build compute
up:
	docker compose up -d --build --remove-orphans
down:
	docker compose down --remove-orphans
logs:
	docker compose logs -f
watch:
	docker compose watch
