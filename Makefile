.PHONY: clean broker run docker up down logs watch

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

FLOWMETER_DIR = ./app/modules/network_module/FlowMeter
define clone_flowmeter
	@if [ ! -d $(FLOWMETER_DIR) ]; then \
		git clone $(1) $(FLOWMETER_DIR); \
	else \
		echo "FlowMeter already installed"; \
	fi
endef

flow-install:
	$(call clone_flowmeter,https://github.com/deepfence/FlowMeter.git)

flow-install-ssh:
	$(call clone_flowmeter,git@github.com:deepfence/FlowMeter.git)
