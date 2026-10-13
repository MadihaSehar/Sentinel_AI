# syntax=docker/dockerfile:1

# ----------------------------------------------------------------------------- #
# Stage 1 — assemble the recon / scanning toolchain.
#
# SentinelAI runs real external binaries (subfinder, dnsx, httpx, naabu,
# katana, gau, waybackurls, ffuf, nuclei). A tool missing from PATH is treated
# as "not installed": its stage records an error and the scan continues with
# empty results, so a container without these produces hollow findings.
#
# We pull official PREBUILT release binaries (fast and reliable — no
# multi-minute source compiles, and no libpcap/CGO build break for naabu) and
# build only waybackurls from source, since tomnomnom publishes no release
# binary for it. Versions mirror backend/scripts/install_recon_tools.sh.
# Target arch: linux/amd64.
# ----------------------------------------------------------------------------- #
FROM golang:1.23-bookworm AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /out

# ProjectDiscovery tools — prebuilt zips (binary sits at the archive root).
RUN set -eux; \
    for spec in \
        "subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip:subfinder" \
        "dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip:dnsx" \
        "httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip:httpx" \
        "naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip:naabu" \
        "katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip:katana" \
        "nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip:nuclei" \
    ; do \
        url="https://github.com/projectdiscovery/${spec%%:*}"; \
        bin="${spec##*:}"; \
        curl -fsSL "$url" -o pkg.zip; \
        unzip -o pkg.zip "$bin" -d /out; \
        rm pkg.zip; \
    done

# ffuf + gau — prebuilt tarballs.
RUN set -eux; \
    curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar -xz -C /out ffuf; \
    curl -fsSL https://github.com/lc/gau/releases/download/v2.2.2/gau_2.2.2_linux_amd64.tar.gz     | tar -xz -C /out gau

# waybackurls — no official release binary, so compile it (tiny, pure Go, no CGO).
RUN GOBIN=/out GOFLAGS=-trimpath go install github.com/tomnomnom/waybackurls@latest

RUN chmod +x /out/*

# ----------------------------------------------------------------------------- #
# Stage 2 — runtime image.
# ----------------------------------------------------------------------------- #
FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl ca-certificates \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Security toolchain from stage 1 → onto PATH.
COPY --from=tools /out/ /usr/local/bin/

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Pre-pull the official nuclei templates so the first live scan isn't blocked
# on a large download at runtime. Best-effort: a restricted build network must
# not fail the image build — nuclei fetches them on first run otherwise, and
# they can be refreshed any time with `nuclei -update-templates`.
RUN nuclei -update-templates || true

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
