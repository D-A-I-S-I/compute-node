.PHONY: clean venv

venv: venv/touchfile
	. venv/bin/activate; python3 app/main.py
venv/touchfile: app/requirements.txt
	test -d venv || python -m venv venv
	. venv/bin/activate; pip install -Ur app/requirements.txt
	touch venv/touchfile
run-local:
	. venv/bin/activate; python3 app/main.py
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
clean:
	rm -r venv
