# WebTransport TLS Setup (Quick Start)

The bolt-daemon WebTransport endpoint requires TLS (HTTP/3 mandate).
For local/LAN use, generate certs with [mkcert](https://github.com/FiloSottile/mkcert).

## Prerequisites

- mkcert installed (`brew install mkcert` on macOS, or see mkcert docs)
- bolt-daemon built with `--features transport-webtransport`

## Generate Certs

```bash
# One-time: install the local CA into your OS trust store
mkcert -install

# Generate cert + key for localhost and 127.0.0.1
mkcert localhost 127.0.0.1
```

This produces:
- `localhost+1.pem` (certificate chain)
- `localhost+1-key.pem` (private key)

### LAN Hostnames

If other devices on the LAN will connect, include the hostname or IP:

```bash
mkcert localhost 127.0.0.1 myhost.local 192.168.1.50
```

The cert must include a SAN (Subject Alternative Name) matching the
address the browser connects to. Browsers reject certs without a matching SAN.

**Important:** LAN peers must also trust the local CA. Copy the CA cert
(`mkcert -CAROOT` shows the path) and install it on each device.

## Start the Daemon

```bash
bolt-daemon \
  --role offerer \
  --signal rendezvous \
  --room my-room \
  --session my-session \
  --to peer-code \
  --ws-listen 127.0.0.1:9100 \
  --wt-listen 127.0.0.1:4433 \
  --wt-cert localhost+1.pem \
  --wt-key localhost+1-key.pem
```

The daemon starts both WS (port 9100) and WT (port 4433) endpoints.

## Kill-Switch

To disable WebTransport without removing cert flags:

```bash
bolt-daemon ... --wt-listen 127.0.0.1:4433 --wt-cert ... --wt-key ... --no-wt
```

When `--no-wt` is set:
- WT endpoint is **not** spawned
- `bolt.transport-webtransport-v1` capability is **not** advertised
- Browsers fall to WS automatically

## Browser Configuration

The browser transport options:

```typescript
const transport = new BrowserAppTransport({
  daemonUrl: 'ws://localhost:9100',
  webTransportUrl: 'https://localhost:4433',
  // webTransportEnabled: false,  // force WS-only (kill-switch)
});
```

If `webTransportUrl` is not set or `webTransportEnabled` is `false`,
the browser skips WebTransport and connects via WebSocket directly.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Browser falls to WS despite WT configured | Cert not trusted | Run `mkcert -install`, restart browser |
| `ERR_CERT_AUTHORITY_INVALID` | Local CA not in trust store | `mkcert -install` on the connecting device |
| WT works on localhost but not LAN | Missing SAN for LAN IP/hostname | Regenerate cert with LAN address included |
| Safari always uses WS | Expected | Safari does not support WebTransport |
