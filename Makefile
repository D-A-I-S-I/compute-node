.PHONY: clean venv

venv: venv/touchfile
	docker compose up -d broker
	. venv/bin/activate; python3 app/main.py
venv/touchfile: app/requirements.txt
	test -d venv || python -m venv venv
	. venv/bin/activate; pip install -Ur app/requirements.txt
	touch venv/touchfile
broker:
	docker compose up -d --remove-orphans broker
run:
	. venv/bin/activate; python3 app/main.py
docker:
	docker compose run --remove-orphans --build compute
up:
	docker compose up -d --build --remove-orphans
down:
	docker compose down --remove-orphans
logs:
	docker compose logs -f
watch:
	docker compose watch
clean:
	rm -r venv
	docker compose down --remove-orphans
