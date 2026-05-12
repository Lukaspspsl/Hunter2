# Hunter 2 — LLM-driven recon + monitoring
#
# Runs the always-on Python app on Railway: scheduler, dashboard, and the
# terminal REPL (via `docker exec ... hunter2 chat`). The LLM lives on a
# separate RunPod GPU pod, reached over HTTP — there is no model in this image.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget unzip git tar \
        nmap dnsutils iputils-ping \
        chromium \
        nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery + community Go binaries — pinned versions.
ARG SUBFINDER_VERSION=2.11.0
ARG NUCLEI_VERSION=3.2.7
ARG HTTPX_VERSION=1.6.9
ARG DNSX_VERSION=1.2.1
ARG ALTERX_VERSION=0.0.4
ARG NOTIFY_VERSION=1.0.7
ARG FFUF_VERSION=2.1.0
ARG GOWITNESS_VERSION=3.1.1
ARG TRUFFLEHOG_VERSION=3.83.7

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && set -eux; \
    for spec in \
        "subfinder|projectdiscovery/subfinder|v${SUBFINDER_VERSION}|subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip|zip" \
        "nuclei|projectdiscovery/nuclei|v${NUCLEI_VERSION}|nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip|zip" \
        "httpx|projectdiscovery/httpx|v${HTTPX_VERSION}|httpx_${HTTPX_VERSION}_linux_${ARCH}.zip|zip" \
        "dnsx|projectdiscovery/dnsx|v${DNSX_VERSION}|dnsx_${DNSX_VERSION}_linux_${ARCH}.zip|zip" \
        "alterx|projectdiscovery/alterx|v${ALTERX_VERSION}|alterx_${ALTERX_VERSION}_linux_${ARCH}.zip|zip" \
        "notify|projectdiscovery/notify|v${NOTIFY_VERSION}|notify_${NOTIFY_VERSION}_linux_${ARCH}.zip|zip" \
        "ffuf|ffuf/ffuf|v${FFUF_VERSION}|ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz|tar" \
        "gowitness|sensepost/gowitness|${GOWITNESS_VERSION}|gowitness-${GOWITNESS_VERSION}-linux-${ARCH}|raw" \
        "trufflehog|trufflesecurity/trufflehog|v${TRUFFLEHOG_VERSION}|trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz|tar" \
    ; do \
        name=$(echo "$spec" | cut -d'|' -f1); \
        repo=$(echo "$spec" | cut -d'|' -f2); \
        tag=$(echo  "$spec" | cut -d'|' -f3); \
        asset=$(echo "$spec" | cut -d'|' -f4); \
        kind=$(echo  "$spec" | cut -d'|' -f5); \
        url="https://github.com/${repo}/releases/download/${tag}/${asset}"; \
        echo "fetching ${name} <- ${url}"; \
        case "$kind" in \
            zip) curl -fL -o /tmp/a.zip "$url" && unzip -oq /tmp/a.zip -d /tmp/x && \
                 mv /tmp/x/${name} /usr/local/bin/${name} && rm -rf /tmp/a.zip /tmp/x ;; \
            tar) curl -fL -o /tmp/a.tgz "$url" && tar -xzf /tmp/a.tgz -C /tmp ${name} && \
                 mv /tmp/${name} /usr/local/bin/${name} && rm -f /tmp/a.tgz ;; \
            raw) curl -fL -o /usr/local/bin/${name} "$url" ;; \
        esac; \
        chmod +x /usr/local/bin/${name}; \
    done

# gau + waybackurls (no static releases that cover both arches reliably — use go install)
RUN apt-get update && apt-get install -y --no-install-recommends golang-go \
    && GOPROXY=direct go install github.com/lc/gau/v2/cmd/gau@latest \
    && GOPROXY=direct go install github.com/tomnomnom/waybackurls@latest \
    && mv /root/go/bin/gau /root/go/bin/waybackurls /usr/local/bin/ \
    && apt-get purge -y golang-go && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* /root/go

RUN npm install -g wappalyzer && npm cache clean --force

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data/logs /app/data/raw_results /app/data/screenshots /app/data/reports

ENV PYTHONPATH=/app \
    CHROME_BIN=/usr/bin/chromium \
    CHROME_PATH=/usr/bin/chromium

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["python", "-m", "src.main", "scheduler"]
