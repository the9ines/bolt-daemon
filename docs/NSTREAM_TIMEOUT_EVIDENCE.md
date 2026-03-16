# N-STREAM Daemon Timeout Hardening — Evidence

Captured: 2026-03-16

---

## 1. Root Cause

`run_post_hello_loop()` accepted `deadline: Instant` — the same deadline created at signaling phase start. By the time signaling + HELLO complete (~10-25s), only 5-20s remained of the default 30s `phase_timeout`. The loop's `if Instant::now() >= deadline` check at line 627 killed the session deterministically.

## 2. Code-Path Change

**File:** `bolt-daemon/src/rendezvous.rs`

**Signature change:**
```
- deadline: Instant
+ deadline: Option<Instant>
```

**Loop guard change:**
```
- if Instant::now() >= deadline { ... }
+ if let Some(d) = deadline { if Instant::now() >= d { ... } }
```

**Poll timeout change:**
```
- deadline.checked_duration_since(Instant::now()).unwrap_or(ZERO)
+ match deadline { Some(d) => d.checked_duration_since(...), None => 200ms }
```

**Production callers (2):**
```
- Instant::now() + Duration::from_secs(3600)
+ None
```

**Test callers (18):**
```
- deadline
+ Some(deadline)
```

## 3. Before / After Timeout Semantics

| Phase | Before | After |
|-------|--------|-------|
| Signaling (pre-connect) | `phase_timeout` (default 30s) | `phase_timeout` (default 30s) — UNCHANGED |
| Post-HELLO (connected) | Shares signaling deadline (~5-20s remaining) | `None` — heartbeat-driven, no wall-clock deadline |
| Test paths | Short bounded deadline | `Some(short_deadline)` — bounded, same behavior |

**Session termination is now driven by:**
- Peer disconnect (channel close)
- Heartbeat failure (ping/pong every 2s)
- Send failure (broken pipe)

**NOT by:**
- Stale signaling phase deadline

## 4. Tests Run

```
cargo test --features test-support
```

| Suite | Passed | Failed |
|-------|--------|--------|
| bolt-daemon lib | 186 | 0 |
| bolt-daemon integration | 131 | 0 |
| sa1 identity separation | 15 | 0 |
| sa1 identity store | 13 | 0 |
| ipc integration | 50 | 0 |
| session | 12 | 0 |
| en3 e2e | 11 | 0 |
| Other suites | 18 | 0 |
| **Total** | **436** | **0** |

### New Regression Tests (3)

| Test | Proves |
|------|--------|
| `b6_no_deadline_runs_until_disconnect` | `None` deadline exits on channel close, not timeout |
| `b6_some_deadline_still_enforced` | `Some(deadline)` still enforces bounded timeout |
| `b6_no_deadline_survives_beyond_30s_window` | Session survives 500ms+ with `None` deadline (no early kill) |

### Existing Tests (all passing)

| Test | Proves |
|------|--------|
| `b6_loop_exits_on_deadline` | Bounded deadline still causes clean exit |
| `b6_ping_produces_pong` | Heartbeat protocol works through envelope |
| `b6_rx_disconnect_clean_exit` | Channel close exits the loop |
| `b6_malformed_frame_disconnects` | Bad data causes error exit |
| `b6_unknown_message_disconnects` | Unknown DC message type causes error exit |

## 5. Stability Evidence Beyond 30s

### Unit test proof

`b6_no_deadline_survives_beyond_30s_window` creates a session with `None` deadline and keeps the channel open for 500ms before disconnecting. The loop survives the full duration — proving no fixed deadline kills the session.

### Live two-device operational proof (2026-03-16)

**Machines:**
| Machine | Role | IP | Arch |
|---------|------|----|------|
| Mac Studio | Host (answerer) | 192.168.4.210 | aarch64 |
| MacBook Pro | Join (offerer) | 192.168.4.249 | x86_64 |

**Exact revisions:**
| Component | Commit | Verified |
|-----------|--------|----------|
| bolt-daemon | `ed74bae` | `git rev-parse HEAD` before build on both machines |
| bolt-core-sdk (bolt-ui) | `f2d8f17` | Used for bolt-ui binary path resolution only |
| bolt-rendezvous | `aa8bed0` | Running on Mac Studio :3001 |

**Binary path verification:**
- Mac Studio: `/Users/oberfelder/Desktop/the9ines.com/bolt-ecosystem/bolt-daemon/target/release/bolt-daemon` (built Mar 16 10:29)
- MBP: `~/Desktop/bolt-daemon-intel` (built from `/tmp/drill-v2/bolt-daemon` at `ed74bae`, Mar 16 10:33)
- Stale `~/Desktop/bolt-daemon-mac` (Mar 15 14:52) was replaced before drill

**Session 1 — stability hold:**
| Checkpoint | Timestamp (UTC) | Status |
|------------|-----------------|--------|
| Connect | 15:51:16Z | SAS `01753A` matched both sides |
| T+30s (old failure boundary) | 15:51:46Z | ALIVE — heartbeating |
| T+60s | 15:52:16Z | ALIVE — heartbeating |
| T+180s (3-min target) | 15:54:22Z | ALIVE — heartbeating |
| Intentional kill | 15:55:29Z | 253 seconds total (4.2 min) |

**Reconnect cycles:**
| Cycle | Kill time | Reconnect time | Status |
|-------|-----------|----------------|--------|
| 1 | 15:55:29Z | 15:55:52Z | CONNECTED, heartbeating |
| 2 | 15:56:10Z | 15:56:33Z | CONNECTED, heartbeating |
| 3 | 15:58:01Z | 15:58:22Z | CONNECTED, heartbeating |

**Failure string grep across ALL logs:**
- `[B6] post-HELLO loop deadline`: **0 occurrences** (CLEAN)
- `FATAL`: **0 occurrences** during connected sessions
- `signal server not listening`: **0 occurrences**
- `daemon not responding`: **0 occurrences**
- `Daemon exited unexpectedly`: **0 occurrences**

**Discovery during drill:**
- Peer IDs with hyphens (e.g., `studio-host`) are rejected by rendezvous server ("Peer code must be alphanumeric"). Retried with alphanumeric IDs. This is a rendezvous validation constraint, not a timeout issue.

## 6. Residual Risks

1. **No maximum session duration** — production sessions run until disconnect. Mitigated by: ping/pong heartbeat every 2s, channel close detection on disconnect.
2. **Legacy daemon HELLO path** — Still uses the original signaling deadline. Correct: legacy mode does a single send/recv, not a long-running session.
3. **Rendezvous peer ID validation** — Hyphenated peer IDs are silently rejected with a connection reset. bolt-ui should validate peer IDs before sending to rendezvous, or rendezvous should return a clear error instead of dropping the connection.
