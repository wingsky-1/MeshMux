# Agent / Codex guidance

Read docs/PRODUCT.zh-CN.md, docs/FEATURES.zh-CN.md, docs/ARCHITECTURE.zh-CN.md, docs/SECURITY.zh-CN.md and docs/ACCEPTANCE.zh-CN.md before editing. The repository is publicly readable; use only synthetic hostnames, IPs and test keys. Do not copy private infrastructure details.

- Keep one reviewable, independently testable deliverable per PR; run gofmt, go vet, go test, race test and go build.
- No PR may touch production hosts, modify Headscale identities, run an installer or publish a live subscription without the user's explicit operational authorization.
- No arbitrary remote Shell, Caddy/OS firewall mutation hidden inside Web handlers, or logging of subscription URLs, auth secrets, VLESS UUIDs or other private material.
- Treat Web-first, optional Out, Mesh-only devices, install-only public CLI and fail-closed operations as non-negotiable invariants.
- Design first: update FEATURE matrix, acceptance and ADR before changing contracts.
- Failures must expose a stable stage/error code and a recovery path. A green mocked test is not evidence of real VPS/phone integration.
- Do not upgrade runtime components by changing an unpinned latest tag. Pin versions, provenance, hashes and tests before install/upgrade code.
- Current scaffold intentionally rejects every install request. Never remove this protection until the installer is independently testable and reviewed.
