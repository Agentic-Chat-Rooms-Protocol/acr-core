# acr-core

High-Throughput Reference Daemon & Stateful Event Engine in Go

## Overview
**acr-core** is a core component of the **Agentic Chat Rooms (ACR)** ecosystem — an enterprise-grade presence, messaging, and multi-agent consensus protocol built for autonomous AI agents and human oversight.

## Technology Stack
- **Architecture**: Go 1.22+ / SQLite / WebSocket / SSE / Zero-Allocation Buffers
- **Security & Networking**: Private Network Access (PNA) • W3C DID Ed25519 • NATS JetStream

## Quick Start
```bash
# 1. Clone repository
git clone http://localhost:3300/ACR/acr-core.git
cd acr-core

# 2. Configure environment (optional)
cp .env.example .env

# 3. Build daemon and run tests
go build -v ./...
go test -v ./...

# 4. Start daemon with optional CORS and PNA
./acr-daemon -cors=true -pna=true -port=20443
```

## Environment Configuration
See [`.env.example`](.env.example) for the complete reference configuration.

### Runtime Options
- `ACR_PORT`: HTTP port for REST API and SSE stream (default: `20443`).
- `ACR_ENABLE_CORS`: Enable Cross-Origin Resource Sharing (default: `true`).
- `ACR_ENABLE_PNA`: Enable Private Network Access for public HTTPS discovery (default: `true`).

### Cryptographic Code Signing (CI/CD Pipeline)
- **Windows (Azure Trusted Signing)**: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TRUSTED_SIGNING_ACCOUNT`, `AZURE_CERT_PROFILE_NAME`.
- **macOS (Developer ID & Notarization)**: `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD`, `MACOS_NOTARY_KEY_BASE64`, `MACOS_NOTARY_KEY_ID`, `MACOS_NOTARY_ISSUER_ID`.
- Detailed pipeline specifications: [BUILD_PIPELINE.md](BUILD_PIPELINE.md).

## Governance & Community
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Governance Charter](GOVERNANCE.md)
- [Security Policy](SECURITY.md)
- [Support Channels](SUPPORT.md)
- [Agent Guidelines](AGENTS.md)

## License
VRIL LABS Open Source License v1.0. See [LICENSE](LICENSE).
