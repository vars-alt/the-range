.PHONY: help up down logs attack dataset baseline clean
help:
	@echo "up       - build & start the lab target (localhost:8000)"
	@echo "attack   - run the attacker playbook against the target"
	@echo "dataset  - synthesize a labeled telemetry dataset (no stack needed)"
	@echo "baseline - train a baseline detector to validate the dataset"
	@echo "down     - stop the lab"
	@echo "clean    - remove generated data"
up:
	docker compose up -d --build target
	@echo "target up at http://127.0.0.1:8000  (try: curl localhost:8000/health)"
attack:
	docker compose --profile attack run --rm attacker --only all
dataset:
	python telemetry/generate.py -n 5000 -o data
baseline:
	python telemetry/baseline_check.py
down:
	docker compose down
logs:
	tail -f data/logs/access.jsonl
clean:
	rm -rf data/logs data/*.jsonl data/*.csv
