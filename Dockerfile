# --------------------------------------------------------------------------- #
# SupplyGuard — container image
#   docker build -t supplyguard .
#   docker run --rm -v "$(pwd):/src" supplyguard scan /src
#   docker run --rm -v "$(pwd):/src" supplyguard scan /src --format sarif -o /src/results.sarif
# --------------------------------------------------------------------------- #
FROM python:3.11-slim

LABEL org.opencontainers.image.title="SupplyGuard" \
      org.opencontainers.image.description="Software supply-chain security scanner & remediation engine" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG GITLEAKS_VERSION=8.18.4
# From the release's gitleaks_<version>_checksums.txt. A supply-chain scanner must not
# install its own tools from an unverified download.
ARG GITLEAKS_SHA256=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d

RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
 && curl -sSfL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
 && echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c - \
 && tar xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
 && rm /tmp/gitleaks.tgz \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY supplyguard/ ./supplyguard/
# Regular (non-editable) install; semgrep failures now fail the build instead of `|| true`.
RUN pip install . semgrep

# Run as an unprivileged user; mounted repos are scanned read-mostly.
RUN useradd --create-home --uid 10001 scanner \
 && git config --system --add safe.directory '*'
USER scanner
WORKDIR /src

ENTRYPOINT ["supplyguard"]
CMD ["--help"]
