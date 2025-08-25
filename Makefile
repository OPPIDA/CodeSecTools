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
	@docker build -f tests/Dockerfile -t cstools_test .
	@docker run --rm --tty --mount type=bind,src="$$HOME"/.codesectools/config,dst=/root/.codesectools/config,ro cstools_test

test-debug:	## Spawn an interactive shell in the test container to debug
	@docker build -f tests/Dockerfile -t cstools_test .
	@docker run --rm -it --mount type=bind,src="$$HOME"/.codesectools/config,dst=/root/.codesectools/config,ro cstools_test /bin/sh

doc-serve:	## Serve the documentation locally
	@mkdocs serve

doc-deploy:	## Build and deploy docs to the gh-pages branch
	@mkdocs gh-deploy --no-history --force --strict