# MeshMux

**Web-first management for proxy aggregation, private mesh networking, and policy-based egress.**

MeshMux is a proposed self-hosted Go control plane that brings three related workflows into one interface:

- **Proxy aggregation:** manage one or more sing-box Line nodes and publish sing-box / Mihomo subscriptions.
- **Optional policy-based Out:** route selected AI or other destinations from a Line through a managed Out server; a deployment without Out remains fully supported.
- **Private Mesh:** manage Headscale / Tailscale devices, including standalone Mesh-only devices and subnet routers; generate per-device sing-box configurations for a single-VPN proxy + Mesh experience.

One Hub hosts the Web UI. Line/Out hosts perform a single assisted install and subsequently self-manage through a narrow outbound Agent connection. Mesh devices and proxy subscribers are separate entities.

> **Project status: design / scaffolding only. NOT READY TO INSTALL.** No server agent, installer, authenticated Web UI or subscription publisher is implemented. The current CLI skeleton intentionally refuses all installations. Do not deploy this repository to production yet.

## Design baseline

| Document | Purpose |
| --- | --- |
| [Product](docs/PRODUCT.zh-CN.md) | Problem, positioning, non-goals |
| [Features](docs/FEATURES.zh-CN.md) | P0 / P1 feature matrix and acceptance |
| [4A architecture](docs/ARCHITECTURE.zh-CN.md) | Business, application, data, technology |
| [Deployment](docs/DEPLOYMENT.zh-CN.md) | Hub / Line / optional Out views |
| [Enrollment](docs/ENROLLMENT.zh-CN.md) | Install and node pairing sequence |
| [Security](docs/SECURITY.zh-CN.md) | Authentication, credentials, Fail2ban |
| [Diagnostics](docs/OBSERVABILITY.zh-CN.md) | Stages, logs, redaction and errors |
| [User experience](docs/UX.zh-CN.md) | Information architecture and primary flows |
| [Component baseline](docs/VERSIONS.zh-CN.md) | Platform and pinned candidates |
| [Acceptance](docs/ACCEPTANCE.zh-CN.md) | Evidence required before deployment |
| [Roadmap](docs/ROADMAP.zh-CN.md) | PR delivery sequence and first milestone |
| [Development](docs/DEVELOPMENT.zh-CN.md) | Build, tests, contributor workflow |
| [ADRs](docs/adr/) | Individual architecture decisions |

## First milestone

PR0 provides only the design and build scaffold. **PR1** will implement a loopback-only, authenticated, single-admin Web foundation with durable local state, secure session boundaries, read-only health information and an auditable bootstrap plan; it must not enable arbitrary privileged operations.

Development starts on **Debian 13** targeting Linux amd64 and arm64. The initial application uses **Go 1.27.2**; core runtime candidates are sing-box 1.14.3, Headscale 0.29.5 and Caddy 2.11.7. Full binary checksums and provenance must be pinned before any installer can run.

## Working locally

~~~sh
go test ./...
go vet ./...
go build ./cmd/meshmux
~~~

The CLI currently accepts only the planned form of the install command and **rejects execution without side effects**.

## License

Apache-2.0, see [LICENSE](LICENSE).
