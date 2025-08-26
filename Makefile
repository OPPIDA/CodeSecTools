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
	@docker compose build
	@docker compose run --rm test

test-debug:	## Spawn an interactive shell in the test container to debug
	@docker compose build
	@docker compose run --rm test /bin/bash

doc-serve:	## Serve the documentation locally
	@mkdocs serve

doc-deploy:	## Build and deploy docs to the gh-pages branch
	@mkdocs gh-deploy --no-history --force --strict