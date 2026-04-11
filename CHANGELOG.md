# Changelog

## Dev.0.1.2 - 2026-04-11

### Firefox TLS regression recovery

- reverted BUG-014's explicit `CurvePreferences` pinning from both browser-facing MITM TLS configs and the upstream TLS dialer after it regressed Firefox into `SSL_ERROR_NO_CYPHER_OVERLAP` across whitelisted sites
- kept BUG-013's browser-alert preservation, so browser-owned TLS failures are still not rewritten into a second gateway `handshake_failure`

### Routed MITM upstream

- added a raw TCP tunnel mode to gateway↔egress mTLS so the gateway can keep origin-side `tls.Client` termination locally while still using remote egress
- whitelisted MITM upstream dials now honor the existing `Domain -> CIDR -> GeoIP -> Default` routing engine instead of bypassing router/egress entirely
- routed MITM upstream now falls back across route candidates (for example remote egress to direct) while preserving the selected route in connection metrics

### Public dev snapshot refresh

- bumped the default CLI version to `Dev.0.1.2`
- refreshed current-truth and public-facing docs for the routed MITM upstream design
- regenerated the curated `../Prism-public-dev` export tree for the `Dev.0.1.2` public `dev` branch candidate

## Dev.0.1.1 - 2026-04-11

### Firefox TLS compatibility hardening

- Browser-owned TLS failures in the native ECH MITM path are no longer masked by a second gateway-level `handshake_failure` alert.
- Browser-facing MITM TLS configs and the upstream TLS dialer now pin classic curve preferences (`X25519`, `P-256`, `P-384`, `P-521`) instead of inheriting Go 1.26 hybrid post-quantum defaults.
- This keeps the MITM-only / native-ECH gateway architecture unchanged while reducing browser-facing and origin-facing TLS compatibility risk for the public dev line.

### Public dev snapshot refresh

- bumped the default CLI version to `Dev.0.1.1`
- refreshed the public-facing README and deploy notes for the current dev snapshot
- regenerated the curated `../Prism-public-dev` export tree for the `Dev.0.1.1` public `dev` branch candidate

## Dev.0.1.0 - 2026-04-11

### Gateway architecture: MITM-only (BUG-007)

- **Breaking change**: raw L4 relay path removed from TCP gateway. MITM is now the sole handler for whitelisted ECH traffic.
- Root cause of all persistent Firefox SSL errors since Dev.0.0.1 identified as inherent fragility of raw relay path (HRR broken, DNS failures leaked as TLS alerts, relay errors swallowed).
- Go `crypto/tls` now handles HRR, TLS version negotiation, and cipher suite selection automatically on both browser and upstream sides.
- `handleDirect()` and `dialTarget()` functions deleted (~180 lines).
- `handleECH()` simplified to: ECH decrypt → innerSNI → MITM.Handle().

### MITM hardening

- UpstreamDialer now iterates all resolved IPs instead of failing on first IP; combined errors reported via `errors.Join`.
- MITMIssuer uses `singleflight` to deduplicate concurrent certificate generation for the same hostname.
- DirectMITMProxy classifies errors into 8 categories (`dns_resolve`, `dial_refused`, `dial_timeout`, `upstream_tls`, `browser_tls`, `cert_issue`, `relay`, `unknown`) with structured `slog.Debug` logging.
- ConnMetrics.ErrorType now set on all MITM error paths.

### DNS resilience

- Negative cache: failed resolutions cached for 30s to prevent DoH query floods.
- Per-endpoint retry: 1 retry with 500ms delay before moving to next endpoint.
- System DNS fallback: `net.DefaultResolver` used as last resort when all DoH endpoints fail. Controlled by `dns.system_fallback` config.
- Prewarm API: `Prewarm(ctx, domains)` for async bulk resolution of whitelist domains at startup.

### Connection handling

- Semaphore-based connection concurrency limit (`gateway.max_conns`, default 10000). Excess connections receive TLS alert.
- Relay error logging: non-expected errors (excluding EOF, closed, timeout) logged at debug level.
- MITM enabled by default in `configs/prism.yaml` template.
- Gateway warns at startup when MITM is not configured.

### New config surface

- `dns.system_fallback` (bool): enable system DNS fallback.
- `gateway.max_conns` (int): maximum concurrent gateway connections.

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
