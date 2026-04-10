# Prism

Prism is a Go-based ECH/DoH gateway and distributed runtime that supports controller-managed multi-node deployment and local standalone operation.

## Dev.0.0.2

This repository snapshot is the public `dev` line for Prism. It is buildable and deployable, but it is not the `main` branch release surface yet.

## Current supported dev surface

- Supported: `controller`, `dns`, `gateway`, `egress`, `standalone`
- Advanced path: `standalone` with `node.controller`
- New in Dev.0.0.2: whitelist-only MITM gateway (ECH termination + trusted CA leaf issuance)
- Not part of `Dev.0.0.2`: client mode, QUIC/UDP runtime entrypoints

## What's new in Dev.0.0.2

### Whitelist ECH MITM gateway

The gateway can now intercept whitelisted domain traffic using a trusted Prism root CA:

- **ECH termination**: the gateway decrypts the inner ClientHello and identifies the target domain
- **Dynamic leaf issuance**: a per-host TLS leaf certificate is issued on-the-fly, signed by a user-provided Prism CA, with TTL-based caching
- **Upstream TLS dial**: the gateway establishes a separate TLS session to the real origin, with configurable minimum TLS version (down to TLS 1.1 for legacy origins)
- **Bidirectional relay**: application bytes are bridged between the browser and origin connections with idle-timeout and byte-counting metrics
- **DNS dual-path steering**: whitelisted domains are steered to the gateway; non-whitelisted domains get DNS passthrough to the real origin
- **HTTP/3 suppression**: QUIC advertisement is suppressed for MITM-mode traffic (TCP/TLS only in v1)

Enable MITM by adding a `mitm` block to your config and providing a trusted CA certificate:

```yaml
mitm:
  enable: true
  ca_cert: "/etc/prism/mitm/ca-cert.pem"
  ca_key: "/etc/prism/mitm/ca-key.pem"
  upstream_min_version: "1.2"
```

### Bug fixes since Dev.0.0.1

- Fixed ECH `legacy_session_id` not being copied to inner ClientHello (RFC 9849 §7.1 compliance)
- Gateway-side DNS resolution now uses its own TTL cache with per-answer minimum TTL
- DNS resolve budget separated from TCP dial budget (8s vs 5s)
- DoH upstream failures now return `SERVFAIL` instead of `REFUSED`
- Upstream DoH cache ages RR TTLs correctly and no longer caches transient failures
- Routed TCP egress retries all resolved IPs within the selected remote node

## Build

```bash
make build
./prism version
```

Expected version output:

```text
Dev.0.0.2
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
