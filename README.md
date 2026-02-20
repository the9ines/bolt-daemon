# Bolt Daemon

Background Rust service for Bolt Protocol applications.

## What This Is

A minimal, event-driven daemon that provides identity persistence, session orchestration, and transfer management for native Bolt applications.

## Role in the Ecosystem

- Maintains device identity key storage and TOFU pinned peer store.
- Orchestrates peer sessions and transfer lifecycle.
- Provides a local IPC API for applications to initiate and manage transfers.
- Enforces resource limits and policy defaults.

The daemon does not implement UI, protocol changes, or network routing.

## Dependencies

- [bolt-core-sdk](https://github.com/the9ines/bolt-core-sdk) — Protocol implementation

## Included In

- [localbolt-app](https://github.com/the9ines/localbolt-app) — Native multi-platform app
- [bytebolt-app](https://github.com/the9ines/bytebolt-app) — Commercial global app

## Not Included In

- [localbolt-v3](https://github.com/the9ines/localbolt-v3) — Web app, daemon not applicable

## Planned Architecture

```
bolt-daemon/
├── src/
│   ├── main.rs          # Entry point, signal handling, supervised restart
│   ├── identity.rs      # Device key storage, TOFU pinned peer store
│   ├── session.rs       # Peer session lifecycle management
│   ├── transfer.rs      # Transfer orchestration, chunk state machine
│   └── ipc.rs           # Local IPC API (Unix socket / named pipe)
├── Cargo.toml
└── README.md
```

## IPC Interface

The daemon exposes a local-only IPC interface for native apps:

- `connect(peer_id)` — Initiate a session with a known peer
- `send(session_id, file_path)` — Queue a file transfer
- `cancel(transfer_id)` — Cancel an in-progress transfer
- `status()` — Query active sessions and transfers
- `peers()` — List TOFU-pinned peers

## Design Constraints

- Low memory footprint
- Event-driven, no busy polling
- Crash-safe with supervised restarts
- Graceful shutdown with connection draining
- Single-instance enforcement (PID file or socket lock)

## License

MIT
