# Changelog

## Dev.0.0.2 - 2026-04-10

### Whitelist ECH MITM gateway

- Added whitelist-only MITM interception: gateway terminates ECH, issues dynamic leaf certificates from a trusted Prism CA, and bridges application bytes to the real origin via a separate upstream TLS session.
- DNS dual-path steering: whitelisted domains are steered to the gateway; non-whitelisted domains get passthrough to the real origin.
- HTTP/3 advertisement suppressed for MITM-mode traffic (TCP/TLS only in MITM v1).
- MITM leaf certificates are cached by SNI with TTL-based expiry and automatic reissuance.
- Upstream TLS dialer supports configurable minimum TLS version (down to TLS 1.1) for legacy origins.
- New config surface: `mitm.enable`, `mitm.ca_cert`, `mitm.ca_key`, `mitm.upstream_min_version`.
- Config validation enforces `whitelist_path` when `mitm.enable=true` and validates CA file existence.

### Bug fixes

- Fixed ECH `legacy_session_id` not being copied to inner ClientHello (RFC 9849 §7.1 compliance).
- Gateway-side DNS resolution now uses its own TTL cache with per-answer minimum TTL and a dedicated 8s resolve budget.
- DoH upstream failures now return `SERVFAIL` instead of `REFUSED`; upstream cache ages RR TTLs and no longer caches transient failures.
- Routed TCP egress now retries all resolved IPs within the selected remote node.
- Gateway/egress routed path now waits for first upstream TLS record before committing a remote route, preventing premature browser EOF on early target failures.

### Runtime surface changes

- `gateway.listen_udp` config: QUIC/UDP handler starts only when configured.
- QUIC ECH routing uses the same whitelist-first semantics and `Domain -> CIDR -> GeoIP -> Default` route order as TCP.
- Whitelist DoH `A` / `AAAA` / `HTTPS` queries now short-circuit locally, no longer depending on upstream DoH availability.

## Dev.0.0.1 - 2026-04-09

### Public dev snapshot

- finalized the CLI default version as `Dev.0.0.1`
- rewrote the root repository surface for a standalone public `dev` snapshot
- kept `deploy/` as the public deployment entry point
- prepared the repository shape for a curated public export tree

### Included runtime surface

- `controller`
- `dns`
- `gateway`
- `egress`
- `standalone`
- advanced path: `standalone` with `node.controller`

### Not included in this snapshot

- client mode as a release claim
- QUIC/UDP as a release claim
- internal planning, verification, archive, and test assets

### Branch position

- this snapshot is intended for a public `dev` branch
- it is not the `main` branch handoff
