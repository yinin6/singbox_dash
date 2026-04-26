# singbox_dash design

## Product shape

singbox_dash is intended to be a small sing-box control panel with three clear layers:

1. Service orchestration: inbound services, protocol choices, transport settings, ports, users, and enable switches.
2. Security material: certificate profiles that can be reused by several services.
3. Output adapters: sing-box server config, sing-box client config, and subscription/share links.

The current implementation focuses on configuration generation and leaves process control as a later module.

## Current model

- `PanelSettings`: public host, DNS strategy, subscription token.
- `Certificate`: file-based or ACME-style certificate profile.
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
- HTTP
- UDP

## Planned modules

### Runtime manager

Add a sing-box binary path setting, then implement:

- validate generated config with `sing-box check`
- write active config to a configurable path
- start, stop, restart, and status
- view recent logs

### Certificate manager

Extend certificate profiles into:

- manual file upload/path mode
- ACME HTTP-01/TLS-ALPN-01 mode
- expiration detection
- renew and reload hooks

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
