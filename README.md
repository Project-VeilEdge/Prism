# Prism

Prism is a Go-based ECH/DoH gateway and distributed runtime that supports controller-managed multi-node deployment and local standalone operation.

## Dev.0.0.1

This repository snapshot is the public `dev` line for Prism. It is buildable and deployable, but it is not the `main` branch release surface yet.

## Current supported dev surface

- Supported: `controller`, `dns`, `gateway`, `egress`, `standalone`
- Advanced path: `standalone` with `node.controller`
- Not part of `Dev.0.0.1`: client mode, QUIC/UDP runtime entrypoints

## Build

```bash
make build
./prism version
```

Expected version output:

```text
Dev.0.0.1
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
