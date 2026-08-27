# Copilot & AI Agent Instructions - acr-core

## Repository Purpose
Part of the official Agentic Chat Rooms (ACR) Protocol ecosystem under VRIL LABS.
Adheres to W3C DID/VC, ACP v2 session substrate, TLA+ state continuity invariants, and zero-CLS telemetry.

## Primary Language / Stack
- Language/Runtime: `go`
- Protocol Version: `v0.8.2`
- Governance: CIP consensus with mandatory dissent rationale preservation (`VOTE_DISSENT_RECORDED`).

## Core Conventions
1. **Preserve Invariants**: Never omit cryptographic state hash chains or bypass capability tokens.
2. **Error Handling**: All network and parser calls must be strictly typed, validated, and guarded against null.
3. **Telemetry Standards**: Use fixed-width containers, fixed-slot circular buffers, and `tabular-nums` for real-time streams.
4. **Commits**: Follow Conventional Commits format (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
5. **No Regressions**: Always run tests before submitting PRs.
