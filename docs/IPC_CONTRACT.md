# Bolt Daemon IPC Contract

> Version: 0.0.1 (matches daemon v0.0.1)
> Status: Implementation-derived, not yet SemVer-stabilized.

This document defines the IPC protocol between `bolt-daemon` and any external consumer (native app, CLI tool, etc.). It is the **sole reference** an external consumer needs to build a compliant IPC client.

---

## Transport

| Platform | Transport | Default Endpoint |
|----------|-----------|-----------------|
| Unix/macOS | Unix domain socket | `/tmp/bolt-daemon.sock` |
| Windows | Named pipe | `\\.\pipe\bolt-daemon` |

- Socket permissions: `0600` (owner-only on Unix), current-user DACL (Windows).
- Single-client: only one consumer connected at a time. New connections kick the previous client.
- Configurable: daemon accepts `--socket-path <path>` to override the default.

---

## Wire Format: NDJSON

All messages are **newline-delimited JSON** (NDJSON):
- One JSON object per line, terminated by `\n`.
- Maximum line size: **1 MiB** (1,048,576 bytes). Lines exceeding this cause disconnect.
- Encoding: UTF-8.
- Empty lines are ignored.

---

## Message Envelope

Every message uses the same envelope shape:

```json
{
  "id": "evt-0",
  "kind": "event",
  "type": "daemon.status",
  "ts_ms": 1712534400000,
  "payload": { ... }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique message ID. Format: `evt-<monotonic integer>` |
| `kind` | string | `"event"` (daemon → consumer) or `"decision"` (consumer → daemon) |
| `type` | string | Message type identifier (see tables below) |
| `ts_ms` | integer | Unix timestamp in milliseconds |
| `payload` | object | Type-specific payload (see below) |

### Message Kinds

- **`event`**: Daemon → consumer. Informational or prompting.
- **`decision`**: Consumer → daemon. Responses to prompts, commands, or the version handshake.

---

## Connection Lifecycle

### Phase 1: Version Handshake (required, synchronous)

The consumer MUST send a `version.handshake` message as its **first message** within **5 seconds** of connecting. The daemon responds with `version.status`.

**Consumer sends:**

```json
{
  "id": "cli-0",
  "kind": "decision",
  "type": "version.handshake",
  "ts_ms": 1712534400000,
  "payload": {
    "app_version": "0.0.1"
  }
}
```

**Daemon responds:**

```json
{
  "id": "evt-0",
  "kind": "event",
  "type": "version.status",
  "ts_ms": 1712534400001,
  "payload": {
    "daemon_version": "0.0.1",
    "compatible": true
  }
}
```

**Compatibility rule:** `major.minor` must match exactly. Patch may differ.

**Failure modes (all fail-closed — daemon disconnects):**
- No message within 5 seconds
- First message is not `version.handshake`
- Malformed JSON
- Missing `app_version` in payload
- Incompatible version (daemon sends `compatible: false`, then disconnects)

### Phase 1b: Daemon Status (automatic, after compatible handshake)

If the handshake succeeds (`compatible: true`), the daemon immediately emits:

```json
{
  "id": "evt-1",
  "kind": "event",
  "type": "daemon.status",
  "ts_ms": 1712534400002,
  "payload": {
    "connected_peers": 0,
    "ui_connected": true,
    "version": "0.0.1"
  }
}
```

The consumer is now fully connected. `ui_connected` is set to `true` only after this point.

### Phase 2: Normal Operation

After handshake completion, the connection enters a bidirectional event/decision loop:
- Daemon sends events asynchronously.
- Consumer sends decisions in response to prompts.

### Disconnection

- Consumer may disconnect at any time by closing the socket.
- Daemon detects EOF and marks `ui_connected = false`.
- Stale events from previous sessions are drained on new connection.

---

## Event Types (daemon → consumer)

### `daemon.status`

Emitted once after handshake, and potentially on state changes.

```json
{
  "connected_peers": 0,
  "ui_connected": true,
  "version": "0.0.1"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `connected_peers` | integer | Number of connected peer sessions |
| `ui_connected` | boolean | Whether a UI/consumer is connected |
| `version` | string | Daemon version |

### `session.connected`

A peer session has been established.

```json
{
  "remote_peer_id": "base64-encoded-identity-public-key",
  "negotiated_capabilities": ["file_transfer"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `remote_peer_id` | string | Remote peer's identity public key (base64) |
| `negotiated_capabilities` | string[] | Capabilities negotiated for this session |

### `session.sas`

Short Authentication String available for user verification.

```json
{
  "sas": "A1B2C3",
  "remote_identity_pk_b64": "base64-encoded-identity-public-key"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `sas` | string | 6-character uppercase hex SAS code |
| `remote_identity_pk_b64` | string | Remote peer's identity public key (base64) |

### `session.error`

Session-level error occurred.

```json
{
  "reason": "connection_timeout"
}
```

### `session.ended`

Peer session has ended.

```json
{
  "reason": "peer_disconnected"
}
```

### `pairing.request`

A remote peer is requesting to pair. Consumer must respond with a `pairing.decision`.

```json
{
  "request_id": "evt-5",
  "remote_device_name": "iPhone 15",
  "remote_device_type": "mobile",
  "remote_identity_pk_b64": "base64-encoded-key",
  "sas": "A1B2C3",
  "capabilities_requested": ["file_transfer"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | string | Correlation ID — MUST be echoed in the decision response |
| `remote_device_name` | string | Human-readable name of the remote device |
| `remote_device_type` | string | Device type (e.g., "mobile", "desktop") |
| `remote_identity_pk_b64` | string | Remote identity public key (base64) |
| `sas` | string | Short Authentication String for verification |
| `capabilities_requested` | string[] | Capabilities the remote peer is requesting |

### `transfer.incoming.request`

A remote peer wants to send a file. Consumer must respond with a `transfer.incoming.decision`.

```json
{
  "request_id": "evt-10",
  "from_device_name": "Mac",
  "from_identity_pk_b64": "base64-encoded-key",
  "file_name": "photo.jpg",
  "file_size_bytes": 1048576,
  "sha256_hex": "abcd1234...",
  "mime": "image/jpeg"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | yes | Correlation ID |
| `from_device_name` | string | yes | Sender's device name |
| `from_identity_pk_b64` | string | yes | Sender's identity key (base64) |
| `file_name` | string | yes | Name of the file |
| `file_size_bytes` | integer | yes | File size in bytes |
| `sha256_hex` | string | no | SHA-256 hash of file (hex), if available |
| `mime` | string | no | MIME type, if available |

### `transfer.started`

A file transfer has begun.

```json
{
  "transfer_id": "xfer-1",
  "file_name": "photo.jpg",
  "file_size_bytes": 1048576,
  "direction": "send"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `transfer_id` | string | Transfer identifier |
| `file_name` | string | Name of the file |
| `file_size_bytes` | integer | Total file size |
| `direction` | string | `"send"` or `"receive"` |

### `transfer.progress`

Transfer progress update.

```json
{
  "transfer_id": "xfer-1",
  "bytes_transferred": 524288,
  "total_bytes": 1048576,
  "progress": 0.5
}
```

| Field | Type | Description |
|-------|------|-------------|
| `transfer_id` | string | Transfer identifier |
| `bytes_transferred` | integer | Bytes transferred so far |
| `total_bytes` | integer | Total file size |
| `progress` | float | Progress fraction (0.0 to 1.0) |

### `transfer.complete`

Transfer finished.

```json
{
  "transfer_id": "xfer-1",
  "file_name": "photo.jpg",
  "bytes_transferred": 1048576,
  "verified": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `transfer_id` | string | Transfer identifier |
| `file_name` | string | Name of the file |
| `bytes_transferred` | integer | Total bytes transferred |
| `verified` | boolean | Whether integrity verification passed |

---

## Decision/Command Types (consumer → daemon)

### `pairing.decision`

Response to a `pairing.request` event. MUST reference the original `request_id`.

```json
{
  "id": "cli-1",
  "kind": "decision",
  "type": "pairing.decision",
  "ts_ms": 1712534401000,
  "payload": {
    "request_id": "evt-5",
    "decision": "allow_once",
    "note": null
  }
}
```

### `transfer.incoming.decision`

Response to a `transfer.incoming.request` event. MUST reference the original `request_id`.

```json
{
  "id": "cli-2",
  "kind": "decision",
  "type": "transfer.incoming.decision",
  "ts_ms": 1712534402000,
  "payload": {
    "request_id": "evt-10",
    "decision": "allow_once",
    "note": null
  }
}
```

### `file.send`

Command to initiate a file send to the currently connected peer.

```json
{
  "id": "cli-3",
  "kind": "decision",
  "type": "file.send",
  "ts_ms": 1712534403000,
  "payload": {
    "file_path": "/path/to/file.txt"
  }
}
```

### Decision Values

| Value | Meaning |
|-------|---------|
| `allow_once` | Allow this single request |
| `allow_always` | Allow this and future requests from this peer |
| `deny_once` | Deny this single request |
| `deny_always` | Deny this and future requests from this peer |

### Decision Payload Shape

All decision payloads share this structure:

```json
{
  "request_id": "evt-N",
  "decision": "allow_once",
  "note": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `request_id` | string | yes | MUST match the `request_id` from the original event |
| `decision` | string | yes | One of the four decision values |
| `note` | string | no | Optional human-readable note |

---

## Fail-Closed Policy

- If no consumer is connected, the daemon treats all pairing and transfer requests as **denied**.
- If a consumer connects but does not complete the version handshake within 5 seconds, the daemon disconnects.
- If the handshake fails (incompatible, malformed, wrong type), the daemon disconnects.
- If a decision is not received within the daemon's internal timeout, the request is denied.

---

## Invariants and Ordering

1. The **first message** from the consumer MUST be `version.handshake`.
2. The daemon will not emit events (other than `version.status` and `daemon.status`) until after successful handshake.
3. Decision `request_id` fields MUST match the `request_id` from the prompting event. Mismatched IDs are discarded.
4. Unknown message types are logged and ignored (not an error).
5. Extra fields in payloads are preserved (forward-compatible).
6. The `id` field format (`evt-<N>`) is monotonically increasing per daemon process lifetime.

---

## Security Notes

- IPC authentication relies on **filesystem permissions only** (socket `0600` / pipe DACL).
- Any process running as the same OS user can connect and send commands.
- This is within the accepted threat model: same-user access already implies access to identity keys, trust store, and received files.
