# One aggregate gate that mirrors CI exactly (docs/CodingStandards.md section 1).
# Every target here runs in .github/workflows/ci.yml with the same flags.

UV ?= uv
RUN := $(UV) run --frozen

.PHONY: help
help:
	@echo "setup      install the locked environment"
	@echo "check      the full gate: format, lint, types, tests, security, audit, build"
	@echo "format     rewrite files to the canonical format"
	@echo "test       run the test suite with coverage"

.PHONY: setup
setup:
	$(UV) sync --frozen

.PHONY: format
format:
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

.PHONY: format-check
format-check:
	$(RUN) ruff format --check .

.PHONY: lint
lint:
	$(RUN) ruff check .

.PHONY: typecheck
typecheck:
	$(RUN) mypy

.PHONY: test
test:
	$(RUN) pytest --cov --cov-report=term-missing

.PHONY: security
security:
	$(RUN) bandit -c pyproject.toml -q -r src

.PHONY: audit
audit:
	# --strict is deliberately omitted: it fails on the skipped editable install of this
	# package itself, not on a vulnerability. Real advisories still fail the target.
	$(RUN) pip-audit --skip-editable

.PHONY: build
build:
	$(UV) build

.PHONY: check
check: format-check lint typecheck test security audit build

.PHONY: clean
clean:
	rm -rf dist build .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
