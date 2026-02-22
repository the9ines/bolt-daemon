# Compatibility Matrix

Pairs bolt-daemon releases with the minimum compatible bolt-rendezvous tag.

| bolt-daemon tag | bolt-rendezvous tag | Notes |
|-----------------|---------------------|-------|
| `daemon-v0.0.10-ci-pin` | `rendezvous-v0.0.3-ci` | CI pinned to this tag. LAN/overlay/global scope. Hello/ack handshake. `payload_version=1`. |
| `daemon-v0.0.9-rendezvous-hello-retry` | `rendezvous-v0.0.2-naming` or later | Hello retry on peer-not-found. Session discriminator required. `payload_version=1`. |
| `daemon-v0.0.8-overlay-scope` | — | File mode only. No rendezvous signaling required. Overlay scope added. |
| `daemon-v0.0.7-network-scope` | — | File mode only. LAN/global scope. |
| `daemon-v0.0.6-rendezvous` | `rendezvous-v0.0.1` or later | First rendezvous support. No hello/ack. No session. |

## Rules

- **bolt-rendezvous is untrusted by design.** It relays opaque payloads; it does not
  inspect or validate hello/ack/offer/answer contents.
- **Payload version gate is in bolt-daemon.** `payload_version` mismatch between two
  daemon peers causes exit 1. The rendezvous server is version-agnostic.
- **Session filtering is in bolt-daemon.** The rendezvous server does not enforce
  session isolation. Daemon peers ignore signals with non-matching sessions.
- Entries marked `—` for rendezvous tag use file-mode signaling only and do not
  require a rendezvous server.

For two-machine operator instructions, see [docs/TWO_MACHINE_SMOKE.md](TWO_MACHINE_SMOKE.md).
