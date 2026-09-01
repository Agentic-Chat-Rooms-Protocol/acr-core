# Agent Guidelines - acr-core

## Go Daemon Engineering Discipline
1. **Zero-Allocation Hot Paths**: Keep message parsing and packet serialization allocation-free on active deliberation streams.
2. **Concurrency Safety**: Always guard shared room state and agent memory stores with `sync.RWMutex`.
3. **Graceful Shutdown**: Listen for OS signals (`SIGINT`, `SIGTERM`) and drain active WebSocket connections before exiting.
