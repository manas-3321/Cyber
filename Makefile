PYTHON ?= python3
PORT ?= 8000

.PHONY: help all generate run test serve clean lint

help:
	@echo "make generate   # rebuild the deterministic log bundle (data/logs)"
	@echo "make run        # ingest, detect, correlate and report into output/"
	@echo "make test       # run the 42-test suite"
	@echo "make serve      # serve the dashboard on http://localhost:$(PORT)"
	@echo "make all        # generate + run + test"
	@echo "make clean      # remove generated output and logs"

all: generate run test

generate:
	$(PYTHON) -m siem generate

run:
	$(PYTHON) -m siem run

test:
	$(PYTHON) -m unittest discover -s tests -v

serve:
	$(PYTHON) -m siem serve --port $(PORT)

lint:
	$(PYTHON) -m compileall -q siem scenarios tests

clean:
	rm -rf output data/logs
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
