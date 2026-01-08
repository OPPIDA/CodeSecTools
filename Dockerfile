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
FROM python:3.12-slim-bookworm

ARG UID=1000
ARG GID=1000

SHELL ["/bin/bash", "-c"]

RUN apt update -qq && \
    DEBIAN_FRONTEND=noninteractive \
    apt install \
        sudo \
        curl git \
        cloc \
        openjdk-17-jdk-headless maven \
        build-essential bear \
    -y -qq --no-install-recommends

RUN groupadd -g $GID codesectools && \
    useradd -l -u $UID -g codesectools -m codesectools -s /bin/bash && \
    echo "codesectools ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/codesectools && \
    chmod 0440 /etc/sudoers.d/codesectools

USER codesectools
WORKDIR /home/codesectools

RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/home/codesectools/.local/bin:$PATH"

# =========================== SAST tools ===========================
RUN uv venv sasts
ENV PATH="/home/codesectools/sasts:$PATH"
ENV PATH="/home/codesectools/sasts/bin:$PATH"

# Semgrep Community Edition
RUN uv pip install --no-cache semgrep

# Bearer
RUN curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | BINDIR=/home/codesectools/sasts sh

# SpotBugs
RUN curl -sL https://github.com/spotbugs/spotbugs/releases/download/4.9.8/spotbugs-4.9.8.tgz | tar -xzvf - && \
    mv spotbugs-* /home/codesectools/sasts/spotbugs && \
    curl -sL https://search.maven.org/remotecontent?filepath=com/h3xstream/findsecbugs/findsecbugs-plugin/1.14.0/findsecbugs-plugin-1.14.0.jar > /home/codesectools/sasts/spotbugs/plugin/findsecbugs-plugin-1.14.0.jar
ENV PATH="/home/codesectools/sasts/spotbugs/bin:$PATH"

# Cppcheck
RUN sudo apt install -y -qq --no-install-recommends libpcre3-dev && \
    curl -sL https://github.com/danmar/cppcheck/archive/refs/tags/2.19.0.tar.gz | tar -xzvf - && \
    mv cppcheck-* /home/codesectools/sasts/cppcheck && \
    (cd /home/codesectools/sasts/cppcheck && make -j$(nproc) MATCHCOMPILER=yes HAVE_RULES=yes CXXOPTS="-O2" CPPOPTS="-DNDEBUG")
ENV PATH="/home/codesectools/sasts/cppcheck:$PATH"

# =========================== CodeSecTools ===========================
COPY --from=builder --chown=codesectools:codesectools /app /app
ENV PATH="/app/.venv/bin:$PATH"

# https://github.com/sarugaku/shellingham/issues/87
RUN find /app -path "*/shellingham/__init__.py" -exec sed -i 's#raise ShellDetectionFailure()#return ("bash", "/bin/bash")#g' {} \; && \
    cstools --install-completion