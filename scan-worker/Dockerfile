# Scan worker: a Celery worker image with Nuclei on board.
# Kept separate from the control plane so it can be lifted onto its own host
# (or a cloud VPS with a clean egress IP) without touching the rest — see the
# control-plane/scan-plane split (§4.2) and the egress-IP discussion.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip libpq-dev build-essential libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei (pinned). nuclei -update-templates refreshes CVE coverage (§4.1).
ARG NUCLEI_VERSION=3.3.0
RUN curl -sSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ && rm /tmp/nuclei.zip \
    && nuclei -update-templates || true

# External discovery chain (ProjectDiscovery): subfinder -> httpx -> naabu (Step 1).
# Same release-zip pattern as Nuclei. naabu's connect scan needs libpcap (above).
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.0
ARG NAABU_VERSION=2.3.1
RUN set -eux; \
    for spec in "subfinder:${SUBFINDER_VERSION}" "httpx:${HTTPX_VERSION}" "naabu:${NAABU_VERSION}"; do \
        tool="${spec%%:*}"; ver="${spec##*:}"; \
        curl -sSL -o /tmp/$tool.zip \
          "https://github.com/projectdiscovery/$tool/releases/download/v$ver/${tool}_${ver}_linux_amd64.zip"; \
        unzip -o /tmp/$tool.zip -d /usr/local/bin/; \
        rm /tmp/$tool.zip; \
    done

COPY control-plane/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY control-plane/ .

CMD ["celery", "-A", "recon", "worker", "-l", "info", "-Q", "scan"]
