# =========================== Build stage ===========================
FROM astral/uv:python3.12-bookworm AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0

WORKDIR /app
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev --extra test

COPY codesectools /app/codesectools
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev --extra test

# =========================== Test stage ===========================
FROM python:3.12-bookworm AS test

RUN apt update && \
    apt install curl git cloc -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# SASTs
RUN pip install --no-cache semgrep
RUN curl https://static.snyk.io/cli/latest/snyk-linux -o snyk && \
    chmod +x ./snyk && \
    mv ./snyk /usr/local/bin/

COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY tests /app/tests

CMD ["pytest", "--showlocals", "-vvv", "--log-cli-level=INFO"]