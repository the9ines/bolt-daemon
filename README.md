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

## Design Constraints

- Low memory footprint
- Event-driven, no busy polling
- Crash-safe with supervised restarts
- Graceful shutdown with connection draining

## License

MIT
