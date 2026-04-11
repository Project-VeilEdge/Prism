# Prism

Prism is a Go-based ECH/DoH gateway and distributed runtime that supports controller-managed multi-node deployment and local standalone operation.

## Dev.0.1.2

This repository snapshot is the public `dev` line for Prism. It is buildable and deployable, but it is not the `main` branch release surface yet.

## Current supported dev surface

- Supported: `controller`, `dns`, `gateway`, `egress`, `standalone`
- Advanced path: `standalone` with `node.controller`
- Gateway architecture: **MITM-only** — all whitelisted ECH traffic is terminated and re-originated via Go `crypto/tls`
- Not part of `Dev.0.1.2`: client mode, QUIC/UDP live runtime

## What's new in Dev.0.1.2

### Firefox / TLS regression recovery

- Browser-side native-ECH TLS failures are no longer rewritten into a second gateway `handshake_failure` alert.
- BUG-014's explicit `CurvePreferences` pinning has been removed from both browser-facing and upstream MITM TLS configs after it regressed Firefox into `SSL_ERROR_NO_CYPHER_OVERLAP` across whitelisted sites.
- Prism now leaves curve negotiation to Go `crypto/tls` defaults on both MITM TLS edges instead of forcing a classic-only curve list.

### Routed MITM upstream

- Whitelisted MITM traffic no longer bypasses Prism's routing engine.
- The gateway now supports a raw TCP tunnel mode over gateway↔egress mTLS, so routed MITM upstream dials can use remote egress and still keep origin-side `tls.Client` termination on the gateway.
- Routed MITM upstream selection now respects the existing `Domain -> CIDR -> GeoIP -> Default` route order, with remote-egress failure falling back to later candidates such as direct.

### MITM-only gateway architecture (BUG-007)

The gateway has been fundamentally simplified. The previous raw L4 relay path — root cause of persistent Firefox SSL errors across 6 prior bug-fix rounds — has been removed entirely. MITM is now the sole handler for whitelisted ECH traffic:

- **ECH termination**: the gateway decrypts the inner ClientHello and identifies the target domain
- **Dynamic leaf issuance**: per-host TLS leaf certificates signed by a user-provided Prism CA, with singleflight deduplication and TTL-based caching
- **Multi-IP upstream dial**: the gateway resolves origin IPs and iterates all addresses before reporting failure
- **8-category error classification**: structured logging for `dns_resolve`, `dial_refused`, `dial_timeout`, `upstream_tls`, `browser_tls`, `cert_issue`, `relay`, `unknown`
- **DNS resilience**: negative cache (30s), per-endpoint retry, system DNS fallback, and a Prewarm API for bulk startup resolution
- **Connection limits**: semaphore-based concurrency cap (default 10000) with TLS alert on overflow
- **HTTP/3 suppression**: QUIC advertisement is suppressed for MITM-mode traffic (TCP/TLS only)

### MITM configuration

Enable MITM by adding a `mitm` block to your config and providing a trusted CA certificate:

```yaml
mitm:
  enable: true
  ca_cert: "/etc/prism/mitm/ca-cert.pem"
  ca_key: "/etc/prism/mitm/ca-key.pem"        # Must be SEC1 PEM ("EC PRIVATE KEY")
  upstream_min_version: "1.2"
```

> **Note**: MITM is now enabled by default in the config template. The CA key must be in SEC1 PEM format (`"EC PRIVATE KEY"` block type). PKCS#8 (`"PRIVATE KEY"`) is not supported.

### Bug fixes since Dev.0.0.2

- Resolved persistent Firefox SSL errors (PR_END_OF_FILE_ERROR, SSL_ERROR_INTERNAL_ERROR_ALERT, SSL_ERROR_PROTOCOL_VERSION_ALERT, SSL_ERROR_BAD_MAC_READ) by removing raw relay path
- UpstreamDialer iterates all resolved IPs instead of failing on first
- MITMIssuer deduplicates concurrent certificate generation via singleflight
- DNS resolver negative cache prevents DoH query floods on repeated failures
- DNS resolver retries per-endpoint with 500ms delay before fallback
- System DNS fallback (`dns.system_fallback`) as last resort when all DoH endpoints fail
- Relay error logging captures non-expected errors at debug level

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full feature roadmap covering near-term, mid-term, and long-term development plans.

## Build

```bash
make build
./prism version
```

Expected version output:

```text
Dev.0.1.2
```

## Deploy

Prism ships deployment assets in `deploy/`.

To stage a local deploy bundle:

```bash
make bundle
```

That command copies the built binary to `deploy/prism` for packaging. Upload the `deploy/` directory to the target host and run:

```bash
sudo ./deploy/setup.sh
```

Then use `deploy/CHECKLIST.md` to complete configuration and validation.

## Repository layout

- `cmd/` — CLI entrypoint and runtime mode selection
- `internal/` — runtime services and mode implementations
- `pkg/` — shared helper packages
- `api/` — protocol and generated API definitions
- `configs/` — example configuration assets
- `deploy/` — deployment bundle, templates, and service definitions

## Public dev repository boundary

This public `dev` snapshot intentionally excludes internal planning material, verification archives, and test sources. The goal is to publish a clear, buildable repository candidate for the public `dev` branch.
