# =========================== Build stage ===========================
FROM astral/uv:python3.12-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0

WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY uv.lock /app/uv.lock
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-project --no-dev --extra test

COPY codesectools /app/codesectools
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra test

# =========================== Base ===========================
FROM python:3.12-slim-bookworm AS test-base

RUN apt update -qq && \
    DEBIAN_FRONTEND=noninteractive \
    apt install \
        curl git \
        cloc \
        openjdk-17-jdk-headless maven \
        build-essential bear \
    -y -qq --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# =========================== No SAST Tools ===========================
FROM test-base AS no-sast
ENV TEST_TYPE=no-sast

# === Run tests ===
COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY tests /app/tests

CMD ["pytest"]

# =========================== With SAST Tools ===========================
FROM test-base AS with-sast
ENV TEST_TYPE=with-sast

# === Free SAST tools only ===
# Semgrep Community Edition
RUN pip install --no-cache semgrep
# Bearer
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | BINDIR=/usr/bin sh
# SpotBugs
RUN curl -sL https://github.com/spotbugs/spotbugs/releases/download/4.9.8/spotbugs-4.9.8.tgz | tar -xzvf - && \
    mv spotbugs-* /tmp/spotbugs
ENV PATH="/tmp/spotbugs/bin:$PATH"
# Cppcheck
RUN apt update -qq && \
    DEBIAN_FRONTEND=noninteractive apt install cppcheck -y -qq --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# === Run tests ===
COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app
COPY tests /app/tests

CMD ["pytest"]