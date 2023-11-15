run:
	docker compose run --build compute
up:
	docker compose up -d --build
down:
	docker compose down
logs:
	docker compose logs -f
watch:
	docker compose watch
