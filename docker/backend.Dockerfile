# syntax=docker/dockerfile:1

# ----------------------------------------------------------------------------- #
# Stage 1 — build the recon / scanning toolchain.
#
# SentinelAI runs real external binaries (subfinder, dnsx, httpx, naabu,
# katana, gau, waybackurls, ffuf, nuclei). A tool that isn't on PATH is
# treated as "not installed": its stage records an error and the scan
# continues with empty results. Baking the binaries in is what turns a
# hollow run into a live scan. Versions mirror
# backend/scripts/install_recon_tools.sh — pin them; don't float a security
# tool chain on @latest.
# ----------------------------------------------------------------------------- #
FROM golang:1.23-bookworm AS tools

# naabu (gopacket) needs libpcap headers to compile.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out \
    GOFLAGS=-trimpath \
    CGO_ENABLED=1
RUN mkdir -p /out

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.6.6
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.6.9
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.3.1
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@v1.1.0
RUN go install -v github.com/lc/gau/v2/cmd/gau@v2.2.2
RUN go install -v github.com/tomnomnom/waybackurls@latest
RUN go install -v github.com/ffuf/ffuf/v2@v2.1.0
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9

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

# Security toolchain compiled in stage 1 → onto PATH.
COPY --from=tools /out/ /usr/local/bin/

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ .

# Pre-pull the official nuclei templates so the first live scan isn't blocked
# on a large download at runtime. Best-effort: a restricted build network must
# not fail the image build — nuclei will fetch them on first run otherwise, and
# they can be refreshed any time with `nuclei -update-templates`.
RUN nuclei -update-templates || true

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
