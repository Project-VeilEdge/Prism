# Prism Deployment Checklist

> Dev.0.1.2 public-dev note: this checklist matches the current public `dev` snapshot and the deploy bundle under `deploy/`.

## Pre-Deployment

- [ ] VPS provisioned (Ubuntu 24.04, public IP)
- [ ] Domain purchased and DNS provider accessible
- [ ] DNS API credentials ready (e.g. Cloudflare API token for DNS-01)
- [ ] Prism binary compiled for linux/amd64: `GOOS=linux GOARCH=amd64 make release`
- [ ] Optional local deploy bundle prepared with `make bundle`
- [ ] If you used `make bundle`, confirm `deploy/prism` exists beside `setup.sh`

## DNS Setup

- [ ] A record: `prism.example.com` → `<SERVER_IP>`
- [ ] A record: `gateway.prism.example.com` → `<SERVER_IP>`
- [ ] Verify propagation: `dig +short prism.example.com` → `<SERVER_IP>`
- [ ] Verify gateway name: `dig +short gateway.prism.example.com` → `<SERVER_IP>`

## Server Setup

- [ ] Before uploading `deploy/`, ensure `deploy/prism` is already staged there (via `GOOS=linux GOARCH=amd64 make bundle` or an equivalent linux/amd64 binary)
- [ ] Upload `deploy/` directory to server
- [ ] Run `sudo ./deploy/setup.sh`
- [ ] If you want a non-default health/metrics port, edit `deploy/prism.service` to pass `--metrics-addr <addr>` before installing it
- [ ] Edit `/etc/prism/prism.yaml` — replace all `TODO_` markers:
  - [ ] `self_ip` → server's public IP
  - [ ] `base_domain` → your domain (e.g. `prism.example.com`)
  - [ ] `ech.public_name` → same as base_domain
  - [ ] `camouflage.theme` stays `minimal`
- [ ] Edit `/etc/prism/users.yaml` or create users with `prism --mode user create --name alice --file /etc/prism/users.yaml`
- [ ] Edit `/etc/prism/whitelist.yaml` — add target domains
- [ ] Choose certificate runtime mode in `prism.yaml`:
  - [ ] **Option A — Runtime ACME DNS-01:**
    1. Set `certs.mode: acme`
    2. Fill `certs.acme.email`, `certs.acme.domains`, `certs.acme.provider`, and `certs.acme.cert_dir`
    3. Put provider credentials in `/etc/prism/prism.env` (for Cloudflare: `CF_DNS_API_TOKEN=...`)
    4. Confirm `/var/lib/prism/acme/` exists and is writable by the service runtime
  - [ ] **Option B — Manual:** Install PEM files at `/etc/prism/certs/{doh.pem,doh-key.pem,gateway.pem,gateway-key.pem}`
- [ ] Optional: enable MITM mode for whitelist traffic:
  - [ ] Generate or obtain a trusted CA certificate and EC private key in **SEC1 PEM format** (`"EC PRIVATE KEY"` block type; `openssl ecparam -genkey` produces this). PKCS#8 (`"PRIVATE KEY"`) is **not** supported.
  - [ ] Install CA files: `mkdir -p /etc/prism/mitm && cp ca-cert.pem ca-key.pem /etc/prism/mitm/`
  - [ ] Uncomment `mitm:` block in `/etc/prism/prism.yaml` and set `enable: true`
  - [ ] Import the CA certificate into client browsers as a trusted root
  - [ ] Run `prism --mode config validate --config /etc/prism/prism.yaml` to verify MITM config
- [ ] Start service: `systemctl start prism`
- [ ] Check status: `systemctl status prism`
- [ ] Verify camouflage: `curl -sk https://prism.example.com/` → minimal HTML page
- [ ] Verify health: `curl -s http://localhost:8080/health` → `{"status":"ok","connections":0}`
- [ ] Verify metrics: `curl -s http://localhost:8080/metrics | head`

## User Setup

- [ ] Create or review a user entry in `/etc/prism/users.yaml`
- [ ] Record the generated user hash (from `prism --mode user create ...` output or the `hash:` field): `______________`
- [ ] Leave `standalone.allow_legacy_hex_users: false` unless you are intentionally enabling local-only compatibility mode

## Browser Configuration

- [ ] Browser settings → DNS over HTTPS → Custom
- [ ] DoH URL: `https://prism.example.com/dns-query/<HASH>`
- [ ] Test: visit a whitelisted domain (e.g. youtube.com)
  - [ ] Verify DNS response rewrites A record (check with browser dev tools / Network tab)
- [ ] Test: visit a non-whitelisted domain → should resolve normally (direct)

## Validation

- [ ] Camouflage page loads at `https://prism.example.com/`
- [ ] `robots.txt` returns `Disallow: /`
- [ ] DoH A query returns `self_ip` for whitelisted domain
- [ ] DoH HTTPS query returns ECHConfigList with per-user public_name
- [ ] ECH ClientHello accepted and decrypted (check `journalctl -u prism` for `ech_decrypt_ok`)
- [ ] Upstream relay works — whitelisted site loads in browser

## Monitoring

- [ ] Health: `curl http://127.0.0.1:8080/health`
- [ ] Logs: `journalctl -u prism -f`
- [ ] Metrics: `curl http://127.0.0.1:8080/metrics`
- [ ] Confirm `prism_gateway_active_connections` appears in Prometheus output

## Runtime Notes

- [ ] Health and metrics live on the single `--metrics-addr` HTTP listener
- [ ] `gateway.health_listen` is not configured anywhere
- [ ] `certs.mode=acme` is a runtime mode, not a separate post-start manual CLI step

> Dev.0.1.2 runtime note: QUIC/UDP is not part of the shipped runtime surface yet. Client mode remains implementation-only for this snapshot until it has a release-credible input flow and fresh end-to-end smoke evidence. The `standalone` + `node.controller` path exists, but it is an advanced compatibility topology rather than the primary deployment story. MITM mode is the sole gateway architecture for whitelisted traffic — raw L4 relay has been removed. Whitelisted MITM upstream traffic can now use the routing engine through direct or remote egress candidates. See `deploy/prism.yaml.template` for MITM configuration.

## Rollback

If anything goes wrong:
```
systemctl stop prism
journalctl -u prism --no-pager -n 100    # check recent logs
systemctl start prism                      # retry after fix
```
