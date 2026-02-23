# Relay Session Protocol

**Status:** Draft
**Phase:** 5B (relay skeleton)
**Baseline:** `daemon-v0.1.6-relay-envelope-spec`
**Companion:** `docs/RELAY_ENVELOPE_SPEC.md` (envelope wire format)

---

## 1. Purpose

This document specifies the relay session setup protocol: how two peers
connect to a relay, receive a shared session identifier, and transition
into the data forwarding phase defined by the Relay Envelope Specification.

The relay session protocol is a control-plane concern, separate from the
data-plane envelope format. It defines one control message type:
`session_assigned`.

---

## 2. Session Lifecycle

```
Peer A ──TCP──► Relay ◄──TCP── Peer B
         │                       │
         │  WebSocket upgrade    │  WebSocket upgrade
         │                       │
         ◄── session_assigned ──►  (relay sends to both)
         │                       │
         │  ══ data phase ══     │  (relay envelope forwarding)
         │                       │
         X  disconnect           X  teardown
```

1. **Connect:** Both peers open a TCP connection to the relay and upgrade
   to WebSocket (standard HTTP upgrade handshake).

2. **Pair:** The relay accepts exactly two WebSocket connections per session.
   The first peer waits until the second connects. No authentication or
   identification is exchanged during pairing (skeleton limitation).

3. **Assign:** The relay generates a 16-byte CSPRNG session_id and sends
   a `session_assigned` control message to both peers.

4. **Data phase:** Both peers include the assigned session_id in every
   relay envelope (see `RELAY_ENVELOPE_SPEC.md`). The relay validates
   session_id on each frame and forwards to the paired peer.

5. **Teardown:** When either peer disconnects (graceful or abrupt), the
   relay terminates the session. The remaining peer is notified via
   transport-level connection closure.

---

## 3. Control Message: `session_assigned`

### 3.1 Direction

Relay → Peer (sent once per peer per session, immediately after pairing).

### 3.2 Wire Format

```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  type (0x01)  |                   |
+-+-+-+-+-+-+-+-+                   +
|              session_id           |
+             (16 bytes)            +
|                                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Field | Type | Size | Value |
|--------|-------|------|------|-------|
| 0 | `type` | uint8 | 1 byte | `0x01` (session_assigned) |
| 1 | `session_id` | bytes | 16 bytes | Relay-generated CSPRNG identifier |

**Total size:** 17 bytes.

### 3.3 Transport

Sent as a WebSocket binary frame. Peers MUST expect a binary message of
exactly 17 bytes as the first message after WebSocket handshake completion.

### 3.4 Peer Behavior

On receiving `session_assigned`:

1. Verify `type == 0x01`. If not, close the connection (protocol error).
2. Verify total message length == 17 bytes. If not, close the connection.
3. Extract `session_id` from bytes 1..17.
4. Store `session_id` for inclusion in all subsequent relay envelopes.
5. Enter the data phase.

### 3.5 Properties

- Sent exactly once per peer per session.
- Session_id is ephemeral: valid only for the duration of this session.
- Session_id is opaque to peers: they MUST NOT interpret or parse it.
- Session_id is generated via CSPRNG (128-bit, birthday-safe).

---

## 4. Control Message Type Registry

| Type byte | Name | Direction | Status |
|-----------|------|-----------|--------|
| `0x01` | `session_assigned` | Relay → Peer | Defined (this spec) |
| `0x02`–`0x0F` | Reserved | — | Reserved for future control messages |
| `0x10`–`0xFF` | Unassigned | — | Available for future use |

Type bytes `0x02`–`0x0F` are reserved for potential future control messages
(e.g., session_terminated, error, keepalive). They are not defined in this
specification and MUST NOT be sent by the skeleton relay.

---

## 5. Distinguishing Control Messages from Data Envelopes

Both control messages and relay envelopes are sent as WebSocket binary
frames. Peers distinguish them by context and by the first byte:

| First byte | Meaning |
|-----------|---------|
| `0x01` | Control message: `session_assigned` |
| `0x01` (in data phase) | Relay envelope with `version == 1` |

**Disambiguation rule:** The `session_assigned` message is the first
binary message received after the WebSocket handshake. All subsequent
binary messages are relay envelopes. Peers MUST track their phase
(setup vs. data) to disambiguate.

This is intentional for the skeleton. Future versions MAY introduce
explicit framing to distinguish control and data messages without
phase tracking.

---

## 6. Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CTRL_SESSION_ASSIGNED` | `0x01` | Control message type: session_assigned |
| `SESSION_ASSIGNED_SIZE` | `17` bytes | Total size of session_assigned message |

---

## 7. Skeleton Limitations

The following are intentional limitations of the Phase 5B skeleton:

- **No authentication:** Peers are not identified or authenticated.
- **No TLS:** WebSocket connections are plain TCP.
- **Single session:** The relay accepts one pair of peers, then exits.
- **No reconnection:** If a peer disconnects, the session ends.
- **No keepalive:** No ping/pong or heartbeat mechanism.
- **No error signaling:** Invalid envelopes are silently dropped.
- **Sequential pairing:** First connection waits for second.

These limitations will be addressed in subsequent phases.
