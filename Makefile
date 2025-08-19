.PHONY: all install check deploy 
all:
	@echo "make [install|check|doc-serve|doc-deploy]"

install:
	@uv sync --all-extras

check:
	@ruff check --fix
	@ruff format
	@ty check

doc-serve:
	@mkdocs serve

doc-deploy:
	@mkdocs gh-deploy --no-history --force --strict