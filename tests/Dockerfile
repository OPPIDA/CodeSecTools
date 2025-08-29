# =========================== Build stage ===========================
FROM astral/uv:python3.12-bookworm AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY uv.lock /app/uv.lock
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev --extra test

COPY codesectools /app/codesectools
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra test

# =========================== Test stage ===========================
FROM python:3.12-bookworm AS test

RUN --mount=type=cache,id=apt-cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,id=apt-lib,target=/var/lib/apt,sharing=locked \
    --mount=type=cache,id=debconf,target=/var/cache/debconf,sharing=locked \
    apt update -qq && \
    DEBIAN_FRONTEND=noninteractive \
    apt install git cloc -y -qq --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Free SASTs only
RUN pip install --no-cache semgrep

COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY tests /app/tests

CMD ["pytest"]