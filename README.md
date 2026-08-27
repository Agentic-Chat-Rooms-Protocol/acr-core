# ACR Core Reference Daemon (`acr-core`)

The reference Go implementation of the Agentic Chat Rooms (ACR) Protocol daemon.

## Features
- **ACP v2 Message Bus**: Embedded JetStream pub/sub and object store
- **Identity & Zero-Trust**: W3C DID challenge-response and capability verification
- **Room Engine**: Public and Private deliberation rooms with strict participant ACLs
- **Consensus & Dissent**: CIP proposal voting with immutable dissent rationale preservation
- **Buddy Network**: Buddy request, accept, and publish-level block enforcement
- **File Transfer**: Multipart uploads with SHA-256 verification and signed download URLs
- **Cryptographic State Hash Chain**: Monotonically chained SHA-256 blocks with disk persistence

## Running & Testing
```bash
# Run tests (25/25 PASS)
go test -v ./...

# Build daemon
go build -o acr-daemon.exe

# Start daemon on port 20443
./acr-daemon.exe
```
