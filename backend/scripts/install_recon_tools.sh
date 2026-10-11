#!/usr/bin/env bash
#
# Installs the Phase-3 recon toolset (subfinder, dnsx, httpx, naabu) via Go.
# Pin versions explicitly; don't float on @latest for a security tool chain.
#
# Usage: ./install_recon_tools.sh
# Requires: Go 1.21+ on PATH.

set -euo pipefail

SUBFINDER_VERSION="v2.6.6"
DNSX_VERSION="v1.2.1"
HTTPX_VERSION="v1.6.9"
NAABU_VERSION="v2.3.1"
KATANA_VERSION="v1.1.0"
GAU_VERSION="v2.2.2"
WAYBACKURLS_VERSION="latest"  # tomnomnom doesn't tag releases consistently
FFUF_VERSION="v2.1.0"
NUCLEI_VERSION="v3.3.9"

command -v go >/dev/null 2>&1 || {
    echo "Go is required but was not found on PATH. Install Go 1.21+ first." >&2
    exit 1
}

echo "Installing subfinder ${SUBFINDER_VERSION}..."
go install -v "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"

echo "Installing dnsx ${DNSX_VERSION}..."
go install -v "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"

echo "Installing httpx ${HTTPX_VERSION}..."
go install -v "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"

echo "Installing naabu ${NAABU_VERSION}..."
echo "NOTE: naabu's SYN-scan mode needs libpcap-dev and CAP_NET_RAW / root."
go install -v "github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}"

echo "Installing katana ${KATANA_VERSION}..."
go install -v "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"

echo "Installing gau ${GAU_VERSION}..."
go install -v "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}"

echo "Installing waybackurls (${WAYBACKURLS_VERSION})..."
go install -v "github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}"

echo "Installing ffuf ${FFUF_VERSION}..."
go install -v "github.com/ffuf/ffuf/v2@${FFUF_VERSION}"

echo "Installing nuclei ${NUCLEI_VERSION}..."
go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"
echo "NOTE: run 'nuclei -update-templates' once after install to pull the official template repo."

GOBIN="$(go env GOPATH)/bin"
echo ""
echo "Done. Binaries installed to: ${GOBIN}"
echo "Make sure that directory is on PATH, e.g.:"
echo "  export PATH=\"\$PATH:${GOBIN}\""
echo ""
echo "Verify with:"
echo "  subfinder -version && dnsx -version && httpx -version && naabu -version"
echo "  katana -version && gau --version && waybackurls -h && ffuf -V && nuclei -version"
