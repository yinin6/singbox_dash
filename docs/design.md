# singbox_dash design

## Product shape

singbox_dash is intended to be a small sing-box control panel with three clear layers:

1. Service orchestration: inbound services, protocol choices, transport settings, ports, users, and enable switches.
2. Security material: certificate profiles that can be reused by several services.
3. Output adapters: sing-box server config, sing-box client config, and subscription/share links.

The current implementation focuses on configuration generation and leaves process control as a later module.

## Current model

- `PanelSettings`: public host, DNS strategy, subscription token.
- `Certificate`: manual, self-signed, or ACME certificate profile with status and expiry tracking.
- `Service`: protocol, listen address, port, TLS, transport, path, method, and users.
- `User`: name, UUID, and password.

Supported protocol targets in the prototype:

- VLESS
- Trojan
- Hysteria2
- Shadowsocks

Supported transport knobs:

- TCP
- WebSocket
- gRPC
- HTTP/H2
- UDP

VLESS users can set `flow=xtls-rprx-vision` and choose standard TLS or Reality. Reality stores the server private key, public key, short ID, handshake target, and uTLS fingerprint at the service level because it replaces certificate-backed TLS for that inbound. The default VLESS profile is TCP + TLS + Vision for cross-client compatibility. The panel intentionally does not emit Xray-only `xhttp` or `seed` options into sing-box configs until sing-box supports compatible fields.

## Planned modules

### Runtime manager

The panel now has a local process manager mode:

- validate generated config with `sing-box check`
- write active config to a configurable path
- stop the previous managed sing-box process by PID
- start `sing-box run -c <config>`
- expose status, PID, config path, and log path

Still planned:

- log tail endpoint
- systemd mode for production servers
- health probes and automatic recovery
- reload hooks after certificate renewal

### Certificate manager

Certificate profiles now cover:

- manual file upload/path mode
- self-signed mode for local smoke tests and private deployments
- ACME HTTP-01, TLS-ALPN-01, and DNS-01 modes through `acme.sh`
- expiration detection
- renew actions

Still planned:

- scheduled auto-renew worker
- sing-box reload hooks after successful renewal
- provider-specific validation hints for DNS credentials

### Access control

Before remote deployment:

- panel login
- session cookies
- optional one-time setup token
- audit log for config changes

### Import/export

Future adapters can include:

- Clash Meta subscription
- sing-box client profiles per platform
- QR code output for share links
- backup and restore of `data/state.json`

## Deployment note

The panel should bind to `127.0.0.1` by default. If it is exposed through a reverse proxy, put HTTPS and authentication in front of it.
