# --------------------------------------------------------------------------- #
# SupplyGuard — Production Docker Image
# --------------------------------------------------------------------------- #
# Usage:
#   docker build -t supplyguard .
#   docker run --rm -v $(pwd):/src supplyguard scan /src
#   docker run --rm -v $(pwd):/src supplyguard scan /src --format sarif -o /src/results.sarif
# --------------------------------------------------------------------------- #

FROM python:3.11-slim AS base

# Metadata
LABEL maintainer="SupplyGuard Maintainers"
LABEL description="AI-Aware Software Supply Chain Security Scanner & Self-Heal Engine"

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies for Gitleaks
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
ARG GITLEAKS_VERSION=8.18.4
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_amd64.tar.gz" \
    | tar xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# --------------------------------------------------------------------------- #
# Install SupplyGuard
# --------------------------------------------------------------------------- #

WORKDIR /app

# Copy dependency files first for Docker layer caching
COPY pyproject.toml requirements.txt ./
COPY supplyguard/ ./supplyguard/

# Install the package and optional semgrep
RUN pip install --no-cache-dir -e . && \
    pip install --no-cache-dir semgrep || true

# Default working directory for scans
WORKDIR /src

ENTRYPOINT ["supplyguard"]
CMD ["--help"]
