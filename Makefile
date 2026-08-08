.PHONY: install lint fmt type test cov ci clean run

install:
	uv sync --all-extras

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff format .
	uv run ruff check --fix .

type:
	uv run mypy orchestrator tools phase1

test:
	uv run pytest -q

cov:
	uv run pytest --cov --cov-report=term-missing --cov-report=xml

ci: lint type test

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

run:
	uv run truthgate --help
