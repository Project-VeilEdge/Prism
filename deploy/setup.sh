#!/usr/bin/env bash
#
# setup.sh — Phase C deployment script for Prism ECH Gateway.
#
# Prepares a fresh Ubuntu 24.04 VPS for standalone Prism operation.
# Idempotent: safe to run multiple times.
#
# Usage:
#   sudo ./deploy/setup.sh
#
# Prerequisites:
#   - Ubuntu 24.04 (or compatible)
#   - Root or sudo
#   - Prism binary in the same directory as this script (deploy/prism)
#     OR already installed at /usr/local/bin/prism

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${BOLD}==> $*${NC}"; }

# --- Pre-flight ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (or with sudo)."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_DIR="/etc/prism"
CERT_DIR="/etc/prism/certs"
PRISM_ENV_FILE="$CONFIG_DIR/prism.env"
DEFAULT_ACME_CERT_DIR="/var/lib/prism/acme"
ACME_CERT_DIR="${ACME_CERT_DIR:-}"
ECH_DIR="/etc/prism"
DATA_DIR="/var/lib/prism"
LOG_DIR="/var/log/prism"
BINARY_SRC="${SCRIPT_DIR}/prism"
BINARY_DST="/usr/local/bin/prism"

trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

load_env_file_defaults() {
    local env_file="$1"
    [[ -f "$env_file" ]] || return 0

    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "$line")"
        [[ -z "$line" || "${line:0:1}" == "#" ]] && continue
        if [[ "$line" =~ ^export[[:space:]]+ ]]; then
            line="$(trim "${line#export}")"
        fi
        if [[ ! "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            warn "Skipping unsupported environment line in $env_file: $line"
            continue
        fi

        local key="${BASH_REMATCH[1]}"
        local value
        value="$(trim "${BASH_REMATCH[2]}")"

        if [[ -n "${!key+x}" ]]; then
            continue
        fi

        if [[ "$value" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
            value="${value//\\\"/\"}"
            value="${value//\\\\/\\}"
        elif [[ "$value" =~ ^\'(.*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi

        export "$key=$value"
    done < "$env_file"
}

# ============================================================
# Step 1: Create directory structure
# ============================================================
step "Step 1: Creating directory structure"

for dir in "$CONFIG_DIR" "$CERT_DIR" "$DATA_DIR" "$LOG_DIR"; do
    if [[ -d "$dir" ]]; then
        info "$dir already exists"
    else
        mkdir -p "$dir"
        chmod 0750 "$dir"
        info "Created $dir"
    fi
done

# ============================================================
# Step 2: Install binary
# ============================================================
step "Step 2: Installing prism binary"

if [[ -f "$BINARY_SRC" ]]; then
    install -m 0755 "$BINARY_SRC" "$BINARY_DST"
    info "Installed $BINARY_DST from $BINARY_SRC"
elif [[ -f "$BINARY_DST" ]]; then
    info "$BINARY_DST already exists, skipping copy"
else
    error "No prism binary found."
    error "Either place it at $BINARY_SRC or pre-install to $BINARY_DST."
    error "Build with: make release (on your dev machine)"
    exit 1
fi

# ============================================================
# Step 3: Generate ECH keys (if not present)
# ============================================================
step "Step 3: ECH key generation"

if [[ -f "$ECH_DIR/ech-key.pem" ]]; then
    info "ECH keys already exist at $ECH_DIR/ech-key.pem, skipping"
else
    info "Generating ECH key pair..."
    "$BINARY_DST" --mode keygen --key-dir "$ECH_DIR"
    chmod 0600 "$ECH_DIR/ech-key.pem"
    chmod 0644 "$ECH_DIR/ech-pubkey.pem"
    info "ECH keys generated: $ECH_DIR/ech-key.pem, $ECH_DIR/ech-pubkey.pem"
fi

# ============================================================
# Step 4: Create example config files (if not present)
# ============================================================
step "Step 4: Creating config files"

if [[ -f "$CONFIG_DIR/prism.yaml" ]]; then
    info "$CONFIG_DIR/prism.yaml already exists, skipping"
else
    if [[ -f "$SCRIPT_DIR/prism.yaml.template" ]]; then
        cp "$SCRIPT_DIR/prism.yaml.template" "$CONFIG_DIR/prism.yaml"
        info "Copied prism.yaml.template to $CONFIG_DIR/prism.yaml"
    else
        warn "No prism.yaml.template found in $SCRIPT_DIR"
        warn "You will need to create $CONFIG_DIR/prism.yaml manually"
    fi
fi

if [[ ! -f "$CONFIG_DIR/users.yaml" ]]; then
    cat > "$CONFIG_DIR/users.yaml" << 'EOF'
users:
  - id: alice
    token: ""
    active: true
  - id: bob
    token: "replace-with-a-real-token"
    active: true
EOF
    info "Created example $CONFIG_DIR/users.yaml"
else
    info "$CONFIG_DIR/users.yaml already exists, skipping"
fi

if [[ ! -f "$CONFIG_DIR/whitelist.yaml" ]]; then
    cat > "$CONFIG_DIR/whitelist.yaml" << 'EOF'
domains:
  - youtube.com
  - www.youtube.com
  - .googleapis.com
  - .googlevideo.com
  - .ytimg.com
  - .gstatic.com
EOF
    info "Created example $CONFIG_DIR/whitelist.yaml"
else
    info "$CONFIG_DIR/whitelist.yaml already exists, skipping"
fi

if [[ ! -f "$CONFIG_DIR/routing.yaml" ]]; then
    cat > "$CONFIG_DIR/routing.yaml" << 'EOF'
egress_nodes:
  - name: direct
    address: ""

rules:
  - match: { default: true }
    egress: direct
EOF
    info "Created example $CONFIG_DIR/routing.yaml"
else
    info "$CONFIG_DIR/routing.yaml already exists, skipping"
fi

if [[ ! -f "$PRISM_ENV_FILE" ]]; then
    cat > "$PRISM_ENV_FILE" << 'EOF'
# Prism environment variables.
# Uncomment and set as needed for runtime ACME DNS-01:
# CF_DNS_API_TOKEN=your-cloudflare-api-token
EOF
    chmod 0600 "$PRISM_ENV_FILE"
    info "Created $PRISM_ENV_FILE"
else
    info "$PRISM_ENV_FILE already exists, skipping"
fi

# ============================================================
# Step 5: Prepare certificate runtime
# ============================================================
step "Step 5: Preparing certificate runtime"

CERT_MODE="${CERT_MODE:-$(sed -n '/^certs:/,/^[^[:space:]]/s/^[[:space:]]*mode:[[:space:]]*"\{0,1\}\([^"#[:space:]]*\)"\{0,1\}.*/\1/p' "$CONFIG_DIR/prism.yaml" | head -n 1)}"
CERT_MODE="${CERT_MODE:-manual}"
ACME_PROVIDER="${ACME_PROVIDER:-$(sed -n '/^certs:/,/^[^[:space:]]/s/^[[:space:]]*provider:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}.*/\1/p' "$CONFIG_DIR/prism.yaml" | head -n 1)}"
ACME_PROVIDER="$(trim "${ACME_PROVIDER:-cloudflare}")"
ACME_CERT_DIR="${ACME_CERT_DIR:-$(sed -n '/^certs:/,/^[^[:space:]]/s|^[[:space:]]*cert_dir:[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}.*|\1|p' "$CONFIG_DIR/prism.yaml" | head -n 1)}"
ACME_CERT_DIR="$(trim "${ACME_CERT_DIR:-$DEFAULT_ACME_CERT_DIR}")"

load_env_file_defaults "$PRISM_ENV_FILE"

case "$CERT_MODE" in
    manual)
        if [[ -f "$CERT_DIR/doh.pem" ]]; then
            info "Manual TLS certs already exist at $CERT_DIR/doh.pem, skipping placeholder generation"
        else
            info "Generating self-signed manual TLS placeholders..."
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                -keyout "$CERT_DIR/doh-key.pem" -out "$CERT_DIR/doh.pem" \
                -days 30 -nodes -batch \
                -subj "/CN=prism-placeholder" \
                -addext "subjectAltName=DNS:localhost,DNS:*.localhost" \
                2>/dev/null
            cp "$CERT_DIR/doh.pem" "$CERT_DIR/gateway.pem"
            cp "$CERT_DIR/doh-key.pem" "$CERT_DIR/gateway-key.pem"
            chmod 0600 "$CERT_DIR"/*-key.pem
            chmod 0644 "$CERT_DIR"/doh.pem "$CERT_DIR"/gateway.pem
            info "Self-signed manual certs generated in $CERT_DIR/"
            warn "Replace these placeholder files before production use."
        fi
        ;;
    acme)
        mkdir -p "$ACME_CERT_DIR"
        chmod 0750 "$ACME_CERT_DIR"
        case "$ACME_PROVIDER" in
            cloudflare)
                if [[ -z "${CF_DNS_API_TOKEN:-}" ]]; then
                    error "acme mode with provider=cloudflare requires CF_DNS_API_TOKEN in exported shell env or $PRISM_ENV_FILE"
                    exit 1
                fi
                ;;
            *)
                warn "Ensure provider-specific DNS credentials for ${ACME_PROVIDER} are present in exported shell env or $PRISM_ENV_FILE"
                ;;
        esac
        info "ACME mode selected; prism will load, obtain, and renew certificates at runtime in $ACME_CERT_DIR"
        ;;
    *)
        error "unsupported certs.mode: $CERT_MODE"
        exit 1
        ;;
esac

# ============================================================
# Step 6: Set capabilities on binary
# ============================================================
step "Step 6: Setting binary capabilities"

if command -v setcap &>/dev/null; then
    setcap 'cap_net_bind_service,cap_net_admin=+ep' "$BINARY_DST"
    info "Set CAP_NET_BIND_SERVICE + CAP_NET_ADMIN on $BINARY_DST"
else
    warn "setcap not found. Installing libcap2-bin..."
    apt-get update -qq && apt-get install -y -qq libcap2-bin > /dev/null 2>&1
    setcap 'cap_net_bind_service,cap_net_admin=+ep' "$BINARY_DST"
    info "Set CAP_NET_BIND_SERVICE + CAP_NET_ADMIN on $BINARY_DST"
fi

# ============================================================
# Step 7: Install systemd service
# ============================================================
step "Step 7: Installing systemd service"

if [[ -f "$SCRIPT_DIR/prism.service" ]]; then
    cp "$SCRIPT_DIR/prism.service" /etc/systemd/system/prism.service
    chmod 0644 /etc/systemd/system/prism.service
    systemctl daemon-reload
    systemctl enable prism.service
    info "Installed and enabled prism.service"
else
    error "prism.service not found in $SCRIPT_DIR"
    error "Cannot install systemd unit."
    exit 1
fi

# ============================================================
# Summary and next steps
# ============================================================
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}  Prism installation complete${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
echo "  Binary:    $BINARY_DST"
echo "  Config:    $CONFIG_DIR/"
echo "  Data:      $DATA_DIR/"
echo "  ECH keys:  $ECH_DIR/ech-key.pem"
echo "  TLS certs: $CERT_DIR/"
echo "  Service:   /etc/systemd/system/prism.service"
echo ""
echo -e "${BOLD}Next steps:${NC}"
echo ""
echo "  1. Edit config — fill in your domain and server IP:"
echo "     vi $CONFIG_DIR/prism.yaml"
echo "     Replace all TODO markers with actual values and keep camouflage.theme=minimal."
echo ""
echo "  2. DNS records — create these at your DNS provider:"
echo "     A    prism.example.com         → <SERVER_IP>"
echo "     A    gateway.prism.example.com → <SERVER_IP>"
echo ""
echo "  3. TLS certificates — choose one runtime mode in prism.yaml:"
echo "     Option A (ACME DNS-01 managed by prism at startup):"
echo "       1. Set certs.mode: acme and fill certs.acme.* in prism.yaml"
echo "       2. Set provider credentials in exported shell env or $PRISM_ENV_FILE (for cloudflare: CF_DNS_API_TOKEN)"
echo "       3. Start prism; it will obtain and renew certificates under $ACME_CERT_DIR"
echo ""
echo "     Option B (Manual):"
echo "       Install PEM files at:"
echo "         $CERT_DIR/doh.pem"
echo "         $CERT_DIR/doh-key.pem"
echo "         $CERT_DIR/gateway.pem"
echo "         $CERT_DIR/gateway-key.pem"
echo ""
echo "  4. Start the service:"
echo "     systemctl start prism"
echo "     systemctl status prism"
echo "     journalctl -u prism -f"
echo ""
echo "  5. Verify:"
echo "     curl -sk https://prism.example.com/           → minimal camouflage page"
echo "     curl -s http://localhost:8080/health          → {\"status\":\"ok\",\"connections\":0}"
echo "     curl -s http://localhost:8080/metrics | head  → Prometheus metrics"
echo ""
echo "  6. Browser setup:"
echo "     prism --mode user create --name alice --file $CONFIG_DIR/users.yaml"
echo "     Set browser DoH to: https://prism.example.com/dns-query/<hash>"
echo ""
