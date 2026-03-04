#!/usr/bin/env node
// D-E2E-B cross-implementation bidirectional transfer harness.
// Test fixture — not product code. Lives inside bolt-daemon/tests/.
//
// Implements minimum Bolt protocol surface:
//   1. Rendezvous WebSocket signaling (register, hello/ack, SDP/ICE)
//   2. WebRTC DataChannel (offerer)
//   3. Encrypted HELLO exchange (NaCl box, X25519)
//   4. Profile Envelope v1 codec
//   5. File transfer (FileOffer → FileAccept → FileChunk → FileFinish)
//   6. SHA-256 integrity verification (both directions)

import { createHash } from 'node:crypto';
import { parseArgs } from 'node:util';
import nacl from 'tweetnacl';
import WebSocket from 'ws';
import nodeDatachannel from 'node-datachannel';

const { PeerConnection } = nodeDatachannel;

// ── CLI ──────────────────────────────────────────────────────

const { values: args } = parseArgs({
  options: {
    'rendezvous-url': { type: 'string' },
    'room-code': { type: 'string' },
    'session': { type: 'string' },
    'peer-id': { type: 'string' },
    'to': { type: 'string' },
    'send-payload-hex': { type: 'string' },
    'expect-receive-sha256': { type: 'string' },
    'expect-receive-size': { type: 'string' },
    'help': { type: 'boolean' },
  },
  strict: true,
});

if (args.help) {
  console.log(`Usage: node harness.mjs --rendezvous-url <ws://...> --room-code <code> \\
  --session <session> --peer-id <id> --to <daemon_peer_id> \\
  --send-payload-hex <hex> --expect-receive-sha256 <hex> --expect-receive-size <bytes>`);
  process.exit(0);
}

const required = ['rendezvous-url', 'room-code', 'session', 'peer-id', 'to',
  'send-payload-hex', 'expect-receive-sha256', 'expect-receive-size'];
for (const key of required) {
  if (!args[key]) {
    console.error(`BOLT_E2E_BIDIR_FAIL reason=missing_arg_${key}`);
    process.exit(1);
  }
}

const RENDEZVOUS_URL = args['rendezvous-url'];
const ROOM_CODE = args['room-code'];
const SESSION = args['session'];
const PEER_ID = args['peer-id'];
const TO_PEER = args['to'];
const SEND_PAYLOAD = Buffer.from(args['send-payload-hex'], 'hex');
const EXPECT_SHA256 = args['expect-receive-sha256'].toLowerCase();
const EXPECT_SIZE = parseInt(args['expect-receive-size'], 10);

const TOTAL_TIMEOUT_MS = 25_000;
const deadlineTimer = setTimeout(() => {
  console.error('BOLT_E2E_BIDIR_FAIL reason=total_timeout');
  process.exit(1);
}, TOTAL_TIMEOUT_MS);

// ── Helpers ──────────────────────────────────────────────────

function toBase64(buf) {
  return Buffer.from(buf).toString('base64');
}

function fromBase64(str) {
  return Buffer.from(str, 'base64');
}

function sha256hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/** NaCl box seal: nonce(24) || ciphertext → base64 string */
function sealBoxPayload(plaintext, remotePk, localSk) {
  const nonce = nacl.randomBytes(24);
  const cipher = nacl.box(plaintext, nonce, remotePk, localSk);
  const combined = Buffer.alloc(24 + cipher.length);
  combined.set(nonce, 0);
  combined.set(cipher, 24);
  return combined.toString('base64');
}

/** NaCl box open: base64 → split nonce/ciphertext → decrypt */
function openBoxPayload(sealedB64, remotePk, localSk) {
  const data = fromBase64(sealedB64);
  if (data.length < 24) throw new Error('sealed payload too short');
  const nonce = data.subarray(0, 24);
  const ciphertext = data.subarray(24);
  const result = nacl.box.open(ciphertext, nonce, remotePk, localSk);
  if (!result) throw new Error('decryption failed');
  return Buffer.from(result);
}

/** Encode profile-envelope v1 */
function encodeEnvelope(innerJson, remotePk, localSk) {
  const sealed = sealBoxPayload(
    typeof innerJson === 'string' ? Buffer.from(innerJson) : innerJson,
    remotePk, localSk
  );
  return JSON.stringify({
    type: 'profile-envelope',
    version: 1,
    encoding: 'base64',
    payload: sealed,
  });
}

/** Decode profile-envelope v1 */
function decodeEnvelope(raw, remotePk, localSk) {
  const outer = JSON.parse(typeof raw === 'string' ? raw : raw.toString());
  if (outer.type !== 'profile-envelope') throw new Error(`expected profile-envelope, got ${outer.type}`);
  if (outer.version !== 1) throw new Error(`envelope version ${outer.version} != 1`);
  if (outer.encoding !== 'base64') throw new Error(`envelope encoding ${outer.encoding} != base64`);
  return openBoxPayload(outer.payload, remotePk, localSk);
}

function fail(reason) {
  console.error(`BOLT_E2E_BIDIR_FAIL reason=${reason}`);
  process.exit(1);
}

// ── Main ─────────────────────────────────────────────────────

async function main() {
  // Generate ephemeral session keypair
  const sessionKp = nacl.box.keyPair();
  // Generate identity keypair
  const identityKp = nacl.box.keyPair();

  let remoteSessionPk = null;

  // 1. Connect to rendezvous
  const ws = new WebSocket(RENDEZVOUS_URL);
  await new Promise((resolve, reject) => {
    ws.on('open', resolve);
    ws.on('error', (e) => reject(new Error(`ws connect: ${e.message}`)));
    setTimeout(() => reject(new Error('ws connect timeout')), 5000);
  });

  // Register
  ws.send(JSON.stringify({
    type: 'register',
    peer_code: PEER_ID,
    device_name: 'e2e-harness',
    device_type: 'desktop',
  }));

  // Wait for peers response
  const peersMsg = await new Promise((resolve, reject) => {
    const handler = (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'peers') {
        ws.removeListener('message', handler);
        resolve(msg);
      }
    };
    ws.on('message', handler);
    setTimeout(() => reject(new Error('peers timeout')), 5000);
  });

  // 2. Send signaling hello
  ws.send(JSON.stringify({
    type: 'signal',
    to: TO_PEER,
    payload: {
      payload_version: 1,
      session: SESSION,
      room: ROOM_CODE,
      msg_type: 'hello',
      from_peer: PEER_ID,
      to_peer: TO_PEER,
      network_scope: 'lan',
      phase_timeout_secs: 15,
    },
  }));

  // Wait for signaling ack
  const ackPayload = await waitForSignal(ws, (payload) => payload.msg_type === 'ack', 5000);

  // 3. Create PeerConnection + DataChannel
  const pc = new PeerConnection('e2e-harness', { iceServers: [] });

  const dcOpenPromise = new Promise((resolve) => {
    pc.onDataChannel((dc) => {
      // Not expected as offerer, but handle
    });
  });

  // Collect ICE candidates
  const localIceCandidates = [];
  let gatheringDone = false;
  const gatheringPromise = new Promise((resolve) => {
    pc.onGatheringStateChange((state) => {
      if (state === 'complete') {
        gatheringDone = true;
        resolve();
      }
    });
  });

  const localDescPromise = new Promise((resolve) => {
    pc.onLocalDescription((sdp, type) => {
      resolve({ sdp, type });
    });
  });

  pc.onLocalCandidate((candidate, mid) => {
    localIceCandidates.push({ candidate, mid });
  });

  // Create DataChannel (triggers SDP offer generation)
  const dc = pc.createDataChannel('bolt');

  // DC message queue
  const dcMessages = [];
  let dcMessageResolve = null;
  const dcOpenResolve = new Promise((resolve) => {
    dc.onOpen(() => resolve());
  });

  dc.onMessage((msg) => {
    const buf = typeof msg === 'string' ? Buffer.from(msg) : Buffer.from(msg);
    dcMessages.push(buf);
    if (dcMessageResolve) {
      const r = dcMessageResolve;
      dcMessageResolve = null;
      r();
    }
  });

  // Wait for local description
  const localDesc = await withTimeout(localDescPromise, 5000, 'local_description_timeout');

  // Wait for gathering
  await withTimeout(gatheringPromise, 5000, 'ice_gathering_timeout');

  // 4. Send SDP offer + publicKey through rendezvous
  ws.send(JSON.stringify({
    type: 'signal',
    to: TO_PEER,
    payload: {
      type: 'offer',
      data: {
        offer: { type: 'offer', sdp: localDesc.sdp },
        publicKey: toBase64(sessionKp.publicKey),
        peerCode: PEER_ID,
      },
      from: PEER_ID,
      to: TO_PEER,
    },
  }));

  // Send gathered ICE candidates
  for (const { candidate, mid } of localIceCandidates) {
    if (!candidate) continue;
    ws.send(JSON.stringify({
      type: 'signal',
      to: TO_PEER,
      payload: {
        type: 'ice-candidate',
        data: { candidate, sdpMid: mid || '0' },
        from: PEER_ID,
        to: TO_PEER,
      },
    }));
  }

  // Send end-of-candidates
  ws.send(JSON.stringify({
    type: 'signal',
    to: TO_PEER,
    payload: {
      type: 'ice-candidate',
      data: { candidate: '', sdpMid: '0' },
      from: PEER_ID,
      to: TO_PEER,
    },
  }));

  // 5. Wait for SDP answer + drain ICE
  const answerDeadline = Date.now() + 10_000;
  while (Date.now() < answerDeadline) {
    const sig = await waitForSignal(ws, () => true, 10_000);
    const sigType = sig.type || '';

    if (sigType === 'answer') {
      const sdp = sig.data?.answer?.sdp;
      if (!sdp) fail('answer_missing_sdp');
      pc.setRemoteDescription(sdp, 'answer');

      // Extract remote session public key
      const pkB64 = sig.data?.publicKey;
      if (!pkB64) fail('answer_missing_publicKey');
      remoteSessionPk = new Uint8Array(fromBase64(pkB64));
      if (remoteSessionPk.length !== 32) fail('publicKey_not_32_bytes');
      break;
    } else if (sigType === 'ice-candidate') {
      const cand = sig.data?.candidate;
      if (cand) {
        pc.addRemoteCandidate(cand, sig.data?.sdpMid || '0');
      }
    }
  }

  if (!remoteSessionPk) fail('no_answer_received');

  // Drain remaining ICE candidates (bounded)
  drainIceCandidates(ws, pc, 3000);

  // 6. Wait for DataChannel open
  await withTimeout(dcOpenResolve, 10_000, 'dc_open_timeout');

  // 7. HELLO exchange
  // Build and send encrypted HELLO
  const helloInner = JSON.stringify({
    type: 'hello',
    version: 1,
    identityPublicKey: toBase64(identityKp.publicKey),
    capabilities: ['bolt.profile-envelope-v1', 'bolt.file-hash'],
  });
  const helloSealed = sealBoxPayload(
    Buffer.from(helloInner), remoteSessionPk, sessionKp.secretKey
  );
  const helloOuter = JSON.stringify({ type: 'hello', payload: helloSealed });
  dc.sendMessage(helloOuter);

  // Wait for daemon HELLO reply
  const helloReplyBuf = await waitForDcMessage(dcMessages, () => dcMessageResolve, (r) => { dcMessageResolve = r; }, 5000);
  const helloReplyJson = JSON.parse(helloReplyBuf.toString());
  if (helloReplyJson.type !== 'hello') fail(`expected_hello_got_${helloReplyJson.type}`);

  // Decrypt daemon HELLO
  const daemonHelloPlain = openBoxPayload(helloReplyJson.payload, remoteSessionPk, sessionKp.secretKey);
  const daemonHello = JSON.parse(daemonHelloPlain.toString());
  if (daemonHello.type !== 'hello') fail('daemon_hello_type_mismatch');
  if (daemonHello.version !== 1) fail('daemon_hello_version_mismatch');

  // Negotiate capabilities
  const localCaps = ['bolt.profile-envelope-v1', 'bolt.file-hash'];
  const remoteCaps = daemonHello.capabilities || [];
  const negotiated = localCaps.filter((c) => remoteCaps.includes(c));
  if (!negotiated.includes('bolt.profile-envelope-v1')) fail('envelope_not_negotiated');
  if (!negotiated.includes('bolt.file-hash')) fail('file_hash_not_negotiated');

  // 8. Harness → Daemon transfer (send file)
  const sendHash = sha256hex(SEND_PAYLOAD);
  const sendTransferId = 'e2e-ts-to-daemon-001';
  const totalChunks = Math.ceil(SEND_PAYLOAD.length / 16384);

  // FileOffer
  const offerMsg = JSON.stringify({
    type: 'file-offer',
    transferId: sendTransferId,
    filename: 'pattern-a.bin',
    size: SEND_PAYLOAD.length,
    totalChunks,
    chunkSize: 16384,
    fileHash: sendHash,
  });
  dc.sendMessage(encodeEnvelope(offerMsg, remoteSessionPk, sessionKp.secretKey));

  // Wait for FileAccept (skip pings/pongs)
  await waitForEnvelopeMessage(
    dcMessages, () => dcMessageResolve, (r) => { dcMessageResolve = r; },
    remoteSessionPk, sessionKp.secretKey,
    (parsed) => parsed.type === 'file-accept',
    5000
  );

  // Send chunks
  for (let i = 0; i < totalChunks; i++) {
    const start = i * 16384;
    const end = Math.min(start + 16384, SEND_PAYLOAD.length);
    const chunkData = SEND_PAYLOAD.subarray(start, end);
    const chunkMsg = JSON.stringify({
      type: 'file-chunk',
      transferId: sendTransferId,
      chunkIndex: i,
      totalChunks,
      payload: toBase64(chunkData),
    });
    dc.sendMessage(encodeEnvelope(chunkMsg, remoteSessionPk, sessionKp.secretKey));
  }

  // FileFinish
  const finishMsg = JSON.stringify({
    type: 'file-finish',
    transferId: sendTransferId,
  });
  dc.sendMessage(encodeEnvelope(finishMsg, remoteSessionPk, sessionKp.secretKey));

  // Brief pause for daemon to process receive + trigger send
  await sleep(1000);

  // 9. Daemon → Harness transfer (receive file)
  // Daemon should trigger send after successful receive (via BOLT_TEST_SEND_PAYLOAD_PATH)
  // Wait for FileOffer from daemon
  const daemonOffer = await waitForEnvelopeMessage(
    dcMessages, () => dcMessageResolve, (r) => { dcMessageResolve = r; },
    remoteSessionPk, sessionKp.secretKey,
    (parsed) => parsed.type === 'file-offer',
    10_000
  );

  const recvTransferId = daemonOffer.transferId;
  const recvTotalChunks = daemonOffer.totalChunks;
  const recvSize = daemonOffer.size;

  // Send FileAccept
  const acceptMsg = JSON.stringify({
    type: 'file-accept',
    transferId: recvTransferId,
  });
  dc.sendMessage(encodeEnvelope(acceptMsg, remoteSessionPk, sessionKp.secretKey));

  // Receive chunks
  const receivedChunks = [];
  let receivedBytes = 0;
  for (let i = 0; i < recvTotalChunks; i++) {
    const chunk = await waitForEnvelopeMessage(
      dcMessages, () => dcMessageResolve, (r) => { dcMessageResolve = r; },
      remoteSessionPk, sessionKp.secretKey,
      (parsed) => parsed.type === 'file-chunk',
      5000
    );
    const data = fromBase64(chunk.payload);
    receivedChunks.push(data);
    receivedBytes += data.length;
  }

  // Wait for FileFinish
  await waitForEnvelopeMessage(
    dcMessages, () => dcMessageResolve, (r) => { dcMessageResolve = r; },
    remoteSessionPk, sessionKp.secretKey,
    (parsed) => parsed.type === 'file-finish',
    5000
  );

  // 10. Verify received data
  const reassembled = Buffer.concat(receivedChunks);
  if (reassembled.length !== EXPECT_SIZE) {
    fail(`size_mismatch_expected_${EXPECT_SIZE}_got_${reassembled.length}`);
  }

  const receivedHash = sha256hex(reassembled);
  if (receivedHash !== EXPECT_SHA256) {
    fail(`hash_mismatch_expected_${EXPECT_SHA256}_got_${receivedHash}`);
  }

  // Success
  console.log(`BOLT_E2E_BIDIR_OK ts_to_daemon_bytes=${SEND_PAYLOAD.length} daemon_to_ts_bytes=${reassembled.length}`);

  // Cleanup
  clearTimeout(deadlineTimer);
  dc.close();
  pc.close();
  ws.close();

  // Give a moment for cleanup
  await sleep(200);
  process.exit(0);
}

// ── Async helpers ────────────────────────────────────────────

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function withTimeout(promise, ms, reason) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(reason)), ms);
    promise.then((v) => { clearTimeout(timer); resolve(v); })
      .catch((e) => { clearTimeout(timer); reject(e); });
  });
}

function waitForSignal(ws, predicate, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      ws.removeListener('message', handler);
      reject(new Error('signal_timeout'));
    }, timeoutMs);
    const handler = (data) => {
      try {
        const msg = JSON.parse(data.toString());
        if (msg.type === 'signal' && msg.payload) {
          if (predicate(msg.payload)) {
            clearTimeout(timer);
            ws.removeListener('message', handler);
            resolve(msg.payload);
          }
        }
      } catch { /* skip non-JSON */ }
    };
    ws.on('message', handler);
  });
}

function waitForDcMessage(queue, getResolve, setResolve, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('dc_message_timeout')), timeoutMs);
    const check = () => {
      if (queue.length > 0) {
        clearTimeout(timer);
        resolve(queue.shift());
      } else {
        setResolve(() => {
          clearTimeout(timer);
          if (queue.length > 0) {
            resolve(queue.shift());
          } else {
            reject(new Error('dc_message_empty_after_notify'));
          }
        });
      }
    };
    check();
  });
}

function waitForEnvelopeMessage(queue, getResolve, setResolve, remotePk, localSk, predicate, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryNext = async () => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        reject(new Error('envelope_message_timeout'));
        return;
      }
      try {
        const raw = await waitForDcMessage(queue, getResolve, setResolve, remaining);
        const inner = decodeEnvelope(raw, remotePk, localSk);
        const parsed = JSON.parse(inner.toString());
        if (predicate(parsed)) {
          resolve(parsed);
        } else {
          // Skip non-matching (e.g., pings) and try next
          tryNext();
        }
      } catch (e) {
        reject(e);
      }
    };
    tryNext();
  });
}

function drainIceCandidates(ws, pc, durationMs) {
  const end = Date.now() + durationMs;
  const handler = (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === 'signal' && msg.payload?.type === 'ice-candidate') {
        const cand = msg.payload.data?.candidate;
        if (cand) {
          pc.addRemoteCandidate(cand, msg.payload.data?.sdpMid || '0');
        }
      }
    } catch { /* ignore */ }
  };
  ws.on('message', handler);
  setTimeout(() => ws.removeListener('message', handler), durationMs);
}

// ── Run ──────────────────────────────────────────────────────

main().catch((e) => {
  console.error(`BOLT_E2E_BIDIR_FAIL reason=${e.message}`);
  process.exit(1);
});
