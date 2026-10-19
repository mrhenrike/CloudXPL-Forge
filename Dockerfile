FROM python:3.11-slim AS base

LABEL maintainer="mrhenrike <henrique.santos@uniaogeek.com.br>"
LABEL org.opencontainers.image.source="https://github.com/mrhenrike/CloudXPL-Forge"
LABEL org.opencontainers.image.description="CloudXPL: cloud infrastructure exploitation framework"

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash xpluser

WORKDIR /opt/cloudxpl

COPY pyproject.toml README.md LICENSE ./
COPY cloudxpl/ cloudxpl/

RUN pip install --no-cache-dir ".[dev]"

USER xpluser

ENTRYPOINT ["cloudxpl"]
CMD ["--help"]
