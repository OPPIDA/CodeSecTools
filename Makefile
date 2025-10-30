# Add a help target to a Makefile that will allow all targets to be self documenting
# https://gist.github.com/prwhite/8168133
all:
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

install: 	## Install all Python dependencies and pre-commits
	@uv sync --all-extras
	@.venv/bin/pre-commit install

check:		## Lint, format, and type-check the code
	@ruff check --fix
	@ruff format
	@ty check

test:		## Run tests in a Docker container
	@docker compose build 1>/dev/null
	@docker compose run --rm no-sast
	@docker compose run --rm with-sast

test-force:	## Run tests in a Docker container while ignoring any stored state
	@docker volume rm codesectools_pytest-cache 2>&1 1>/dev/null || true
	@docker compose build 1>/dev/null
	@docker compose run --rm no-sast
	@docker compose run --rm with-sast

test-debug:	## Spawn an interactive shell in the test container to debug
	@docker compose build
	@docker compose run --rm test /bin/bash

docs-serve:	## Serve the documentation locally
	@mkdocs serve --livereload