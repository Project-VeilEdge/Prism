# Prism Feature Roadmap

> Based on the v9 blueprint (`prism-blueprint.md`) and current codebase state as of Dev.0.1.0.
> This document tracks planned features, their dependencies, and implementation priority.
> Last updated: 2026-04-11

---

## Current State Summary

### What's Implemented and Verified

| Component | Status | Notes |
|-----------|--------|-------|
| ECH decryptor | ✅ Done | RFC 9849 compliant, session_id copy, outer_extensions |
| DoH endpoint | ✅ Done | Bearer-token auth, rate limiting, whitelist short-circuit |
| DNS ECH injection | ✅ Done | Per-user SVCB/HTTPS, lazy ECHConfigList build |
| TLS gateway | ✅ Done | **MITM-only** architecture (raw relay removed in Dev.0.1.0) |
| MITM leaf issuer | ✅ Done | Singleflight dedup, TTL cache, auto-reissue |
| MITM upstream dialer | ✅ Done | Multi-IP iteration, TLS 1.1+ support |
| MITM error classification | ✅ Done | 8 categories with structured logging |
| DNS resolver | ✅ Done | TTL cache, negative cache, retry, system fallback, prewarm API |
| Egress routing engine | ✅ Done | Domain/CIDR/GeoIP rules, mTLS frame protocol |
| Egress server | ✅ Done | 4-layer defense, source IP whitelist |
| Controller | ✅ Done | gRPC/mTLS, ConfigSync, NodeReport, UserAudit |
| Camouflage web server | ✅ Done | Minimal theme, SNI-based routing |
| QUIC/UDP handler | ⚠️ Code done | Pending live browser deployment and smoke test |
| Connection concurrency | ✅ Done | Semaphore (default 10000) |
| Relay with metrics | ✅ Done | Byte counting, idle timeout, error logging |

### What's Not Yet Implemented

| Feature | Blueprint Section | Priority |
|---------|-------------------|----------|
| QUIC/HTTP3 MITM | Sprint 8 | **Near-term** |
| Egress TCP tunnel for MITM | Sprint 4 (redesign) | **Near-term** |
| DNS prewarm wiring | Phase 3 | **Near-term** |
| prism-client mode | Sprint 9 | Mid-term |
| TLS fingerprint countermeasures | Sprint 7 | Mid-term |
| splice zero-copy relay | Sprint 9 | Mid-term |
| Hot reload (fsnotify/SIGHUP) | Sprint 7 | Mid-term |
| Docker/containerized deployment | Sprint 10 | Long-term |
| Multi-controller HA | Beyond blueprint | Long-term |
| High-fidelity camouflage (nginx) | Sprint 7 | Long-term |

---

## Near-Term (Next 1-2 Development Cycles)

### N1: QUIC/HTTP3 MITM Design

**Priority**: HIGH — Most ECH-enabled sites use HTTP/3; without QUIC MITM, browsers fall back to TCP which can trigger protocol errors or performance degradation.

**Current state**: The QUIC handler (`internal/quic/`) rewrites the first QUIC Initial packet's outer ClientHello to inner ClientHello for L4 forwarding. This is the same raw-relay approach that was removed from TCP in BUG-007.

**Planned work**:
- Design a QUIC-level MITM that terminates the QUIC connection on the gateway side
- Establish a separate QUIC session to the upstream origin
- Bridge HTTP/3 frames between browser and origin QUIC sessions
- Evaluate `quic-go` library for Go-native QUIC termination
- Handle QUIC connection migration and 0-RTT
- Integrate with existing MITM leaf issuer (TLS within QUIC uses the same certificate infrastructure)

**Dependencies**: None (can start independently)

**Risk**: QUIC MITM is significantly more complex than TCP MITM because QUIC multiplexes streams, has its own congestion control, and connection migration semantics. May need to proxy at HTTP/3 layer rather than QUIC transport layer.

### N2: Egress TCP Tunnel Redesign for MITM Mode

**Priority**: HIGH — Routed egress is currently bypassed in MITM-only mode. Multi-region routing is a core Prism feature.

**Current state**: The egress infrastructure (`Router`, `EgressClient`, egress frame protocol) is preserved but `handleECH()` no longer calls Resolve → Route → Forward. The old approach forwarded raw inner ClientHello bytes through the egress frame protocol, which is incompatible with MITM termination.

**Planned work**:
- Design a TCP tunnel protocol: gateway establishes a TCP tunnel to the egress node, then performs MITM upstream TLS dial through that tunnel
- The gateway terminates browser-side TLS locally (as it does now for direct), but the upstream TLS connection is dialed through the egress tunnel rather than directly
- Egress node acts as a transparent TCP proxy to the target, not a TLS terminator
- Reuse existing egress mTLS authentication and frame protocol header for tunnel setup
- Wire routing back into `handleECH()`: ECH decrypt → innerSNI → Resolve → Route → if routed: tunnel through egress → MITM upstream via tunnel; if direct: MITM upstream directly

**Dependencies**: Requires clear egress tunnel wire protocol design before implementation.

### N3: DNS Prewarm Wiring at Gateway Startup

**Priority**: MEDIUM — The `Prewarm(ctx, domains)` API exists in `internal/resolver/resolver.go` but is not yet called at startup.

**Planned work**:
- Wire `Prewarm()` call in `startGateway()` and `startStandalone()` after whitelist load
- Pass whitelist domain list to resolver prewarm
- Log prewarm results at info level (N domains resolved, M failed)
- Ensure prewarm runs asynchronously and does not block gateway startup

**Dependencies**: None

### N4: Live Browser Deployment and Smoke Test

**Priority**: HIGH — All code changes since Dev.0.0.1 have been verified with unit/integration tests but lack live browser evidence.

**Planned work**:
- Deploy Dev.0.1.0 to test server (139.180.200.84)
- Firefox smoke: verify all prior SSL errors (PR_END_OF_FILE_ERROR, SSL_ERROR_INTERNAL_ERROR_ALERT, etc.) are resolved
- Chrome smoke: verify no ERR_SSL_PROTOCOL_ERROR, ERR_QUIC_PROTOCOL_ERROR
- Test whitelist domains: `.youtube.com`, `.ip.sb`, `.googlevideo.com`
- Validate MITM leaf cert appears in browser certificate viewer
- Measure cold-start DNS resolution latency with negative cache + system fallback

**Dependencies**: N3 (prewarm improves cold-start experience)

---

## Mid-Term (3-6 Development Cycles)

### M1: prism-client Mode

**Priority**: MEDIUM — Enables non-ECH devices (older browsers, mobile apps, IoT) to use Prism.

**Blueprint reference**: Sprint 9, Section 二十一

**Current state**: `internal/client/` package exists with basic structure but is downgraded from the release surface due to lack of release-credible end-to-end smoke.

**Planned work**:
- `client/localdns.go`: local DNS interceptor on `127.0.0.1:10053`
  - Rewrites A/AAAA responses for whitelisted domains to `127.0.0.1`
  - Passes non-whitelisted queries to upstream
- `client/proxy.go`: local TLS proxy on `127.0.0.1:10443`
  - Accepts browser TLS connections using a local CA
  - Wraps the inner ClientHello in ECH and forwards to the Prism gateway
- `ech/encryptor.go`: ECH encryption (inverse of decryptor)
  - Takes a plaintext ClientHello and wraps it in an ECH outer
  - Uses the gateway's published ECHConfig from SVCB records
- Client configuration: gateway address, user hash, local CA path
- End-to-end test: client → gateway → upstream with browser verification

**Dependencies**: N4 (gateway must be proven working first)

### M2: TLS Fingerprint Countermeasures (uTLS)

**Priority**: MEDIUM — Go's `crypto/tls` ServerHello fingerprint (JA3S/JA4S) differs from nginx/OpenSSL, potentially enabling detection.

**Blueprint reference**: Sprint 7, Section 十

**Current state**: MVP approach (no `Server` header, consistent Go fingerprint). Acceptable for many deployments but detectable by advanced analysis.

**Planned work**:
- **Phase 1: Research** — Measure current Go TLS JA3S fingerprint, compare with nginx 1.24/1.26 and OpenSSL 3.x
- **Phase 2: uTLS server-side** — Evaluate `refraction-networking/utls` for server-side ServerHello crafting
  - uTLS server-side support is less mature than client-side; may need custom patches
  - Target: JA3S match with nginx default configuration
- **Phase 3: Integration** — Replace gateway's `tls.Server` with uTLS-wrapped server for camouflage connections
  - MITM browser-facing TLS can stay with standard `crypto/tls` (browser trusts our CA, fingerprint is less relevant)
  - Camouflage (non-ECH) connections are the primary detection surface
- **Fallback**: If uTLS server-side proves impractical, document and support the nginx `ssl_preread` front-end approach (see blueprint Section 十)

**Dependencies**: None (independent research)

### M3: splice Zero-Copy Relay

**Priority**: LOW-MEDIUM — Performance optimization for high-throughput deployments.

**Blueprint reference**: Sprint 9

**Current state**: `internal/relay/pipe.go` uses `io.CopyBuffer` with pooled 16KB buffers via `sync.Pool`.

**Planned work**:
- `relay/splice_linux.go`: Linux-specific `splice(2)` zero-copy path
  - Use `golang.org/x/sys/unix.Splice` for TCP-to-TCP byte transfer
  - Requires both file descriptors to be TCP sockets (not TLS)
  - In MITM mode, splice can only be used for the plaintext relay between `tls.Conn.Read` output and `tls.Conn.Write` input — limited benefit
- Benchmark: compare `io.CopyBuffer` vs `splice` for various payload sizes
- Conditional compilation: `//go:build linux` with fallback to io.CopyBuffer

**Dependencies**: None, but benefit is limited in MITM mode since splice operates below TLS

**Note**: With MITM-only architecture, the relay operates between two `tls.Conn` objects. Splice cannot bypass TLS encryption/decryption. The main benefit would be if a future raw TCP tunnel mode (for egress) is added.

### M4: Hot Reload Completion

**Priority**: MEDIUM — Required for zero-downtime configuration updates in production.

**Blueprint reference**: Sprint 7, Section 十四

**Current state**: `atomic.Pointer` pattern used for whitelist and routing rules. ECH key dual-window exists conceptually but not implemented.

**Planned work**:
- `fsnotify` file watcher for config directory
- SIGHUP handler as manual reload trigger
- ECH key rotation: dual-key window (keep old key for ≥ 2×TTL after rotation)
- TLS certificate hot reload via `GetCertificate` callback
- MITM CA certificate hot reload (flush leaf cache on CA change)
- GeoIP database hot reload with delayed old-reader close

**Dependencies**: None

---

## Long-Term (6+ Development Cycles)

### L1: High-Fidelity Camouflage with nginx Front-End

**Priority**: LOW — Only needed for deployments facing sophisticated TLS fingerprinting analysis.

**Blueprint reference**: Sprint 7, Section 十 (optional enhancement)

**Planned work**:
- nginx `stream` module with `ssl_preread` to transparently route based on SNI
- ECH-bearing connections (matching `*.gw.*`) forwarded to gateway on internal port
- All other connections handled by nginx itself (real TLS fingerprint, real HTTP server)
- Gateway listens on `127.0.0.1:8443` instead of `0.0.0.0:443`
- Deploy guide and nginx configuration templates
- Optional: nginx as ACME certificate manager

**Dependencies**: M2 (understand fingerprint gap first)

### L2: Docker and Container Deployment

**Priority**: LOW-MEDIUM — Simplifies deployment and enables orchestration.

**Blueprint reference**: Sprint 10

**Planned work**:
- Multi-stage Dockerfile (Go build → scratch/distroless runtime)
- `docker-compose.yml` for full distributed topology (controller + dns + gateway + egress)
- Volume mounts for configuration, certificates, GeoIP database
- Health check integration for container orchestrators
- Kubernetes manifests (Deployment, Service, ConfigMap) — stretch goal
- ARM64 cross-compilation support

**Dependencies**: N4 (proven working deployment first)

### L3: Multi-Controller High Availability

**Priority**: LOW — Currently single-controller is sufficient for most deployments.

**Planned work**:
- Evaluate Raft consensus or leader election for controller HA
- SQLite → distributed storage migration path (CockroachDB, etcd, or embedded Raft)
- Config sync protocol changes for multi-writer consistency
- Node failover: automatic re-registration with surviving controller
- Split-brain protection

**Dependencies**: All near-term and mid-term work

### L4: Advanced Monitoring and Observability

**Priority**: LOW-MEDIUM — Production deployments need deeper operational visibility.

**Planned work**:
- Grafana dashboard templates for Prometheus metrics
- Distributed tracing (OpenTelemetry) across gateway → egress hops
- Alert rules for key error conditions (MITM cert failure rate, DNS resolution failure rate, connection saturation)
- Structured log aggregation guidance (Loki, Elasticsearch)
- Per-user bandwidth reporting dashboard

**Dependencies**: N4 (need production metrics first)

### L5: ECH Key Rotation Automation

**Priority**: MEDIUM-LONG — Important for security but manual rotation works for early deployments.

**Planned work**:
- Automated ECH key generation on schedule (e.g., weekly)
- Dual-key window: new key published, old key kept for ≥ 2×DNS TTL
- Controller-driven key distribution to all gateway nodes
- DNS SVCB record update with new ECHConfigList
- Key generation audit log

**Dependencies**: M4 (hot reload infrastructure)

---

## Feature Dependency Graph

```
N1 (QUIC MITM) ──────────────────────────────────┐
N2 (Egress Tunnel) ──────────────────────────────┤
N3 (DNS Prewarm) ─────┐                          │
N4 (Live Smoke) ───────┤                          │
                       ▼                          ▼
                  M1 (Client) ──────────────> L2 (Docker)
                  M2 (uTLS) ────────────────> L1 (nginx)
                  M3 (splice) ──────────────> [limited benefit in MITM mode]
                  M4 (Hot Reload) ──────────> L5 (ECH Key Rotation)
                                              L3 (Multi-Controller HA)
                                              L4 (Monitoring)
```

---

## Blueprint Alignment Notes

This roadmap is derived from the v9 blueprint's Sprint 7-10 plan with the following adjustments:

1. **MITM-only architecture** — The blueprint assumed raw L4 relay as the primary path. Dev.0.1.0 removed raw relay entirely. All future features (QUIC, egress, client) must be designed around MITM termination.

2. **Egress redesign required** — Blueprint Sprint 4 egress design assumed forwarding raw inner ClientHello bytes. MITM-only mode requires a TCP tunnel approach where the gateway performs TLS termination and the egress node is a transparent TCP pipe.

3. **QUIC MITM complexity** — Blueprint Sprint 8 assumed QUIC L4 rewrite (same as TCP raw relay). MITM-only mode requires full QUIC termination, which is significantly more complex and may need an HTTP/3-level proxy.

4. **splice limited benefit** — With MITM-only, relay operates between `tls.Conn` objects. `splice(2)` cannot bypass TLS. Benefit is restricted to a future raw TCP tunnel for egress.

5. **Phase 1-3 sprint numbering** — Blueprint sprints 0-6 are largely complete. This roadmap uses priority tiers (Near/Mid/Long) instead of sequential sprint numbers, reflecting the reality that features can be developed in parallel.

---

## Implementation Notes for Contributors

- All planned work follows the existing Go module structure (`cmd/prism/`, `internal/`, `pkg/`)
- Tests are required for all new features (TDD preferred)
- MITM-related changes should include integration tests with real TLS handshakes
- Config changes must be reflected in `configs/prism.yaml`, `deploy/prism.yaml.template`, and `deploy/CHECKLIST.md`
- New runtime surfaces must be documented in `docs/STATUS.md` before release claims
- Public export boundary: test files and internal docs are excluded from `../Prism-public-dev`
