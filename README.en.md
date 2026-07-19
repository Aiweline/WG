# WG

[简体中文](./README.md) · **English** · [日本語](./README.ja.md)

> Enter a server IP, manage split-routing decisions, and keep system DNS untouched—that is the private-tunnel experience WG is designed to provide.

[WG](https://github.com/Aiweline/WG) is a lightweight intelligent split-tunneling project written in Go. The client has a graphical interface, while the server is managed through scripts and command-line tools. Domain, IP, and CIDR decisions remain editable; deleting a manual override returns the destination to <code>AUTO</code> classification.

> [!NOTE]
> WG provides a usable TCP proxy and encrypted UDP relay. It does not create a TUN device, system routes, firewall, or NAT rules, so it does not alter system DNS. It is not WireGuard-compatible and must not be represented as a system-wide VPN.

## TCP / UDP data plane

`wg-proxy` carries real traffic: TCP mode is a TLS-protected, token-authenticated HTTP/HTTPS CONNECT proxy; UDP mode is a token-authenticated AES-256-GCM protected request/response relay. TCP and UDP can use the same port number, `9518`, because they use separate network protocols.

```sh
# TCP server and local HTTP proxy client
wg-proxy server -listen :9518 -cert ./server-cert.pem -key ./server-key.pem -token-file /etc/wg-proxy/token
wg-proxy client -listen 127.0.0.1:47101 -server SERVER_IP:9518 -ca ./server-cert.pem -token-file ./token

# UDP server and a local relay for a selected UDP target
wg-proxy udp-server -listen :9518 -token-file /etc/wg-proxy/token
wg-proxy udp-client -listen 127.0.0.1:47102 -server SERVER_IP:9518 -target 1.1.1.1:53 -token-file ./token
```

UDP requires an explicit `-target host:port`; it is suited to DNS, games, and other fixed UDP services, not a transparent UDP/TUN implementation.

## Core Ideas

- **Intelligent split routing** — <code>AUTO</code> can classify a destination, while explicit decisions can use <code>TUNNEL</code>, <code>DIRECT</code>, or <code>BLOCK</code>.
- **Managed decisions** — Add domain, IP, and CIDR overrides; removing one restores automatic classification.
- **Private DNS copy** — Read system resolver configuration without changing it, then use an isolated generation and private TTL cache.
- **Client UI, script-based server** — The client exposes connection, routing, DNS, health, and pairing views; the server has no UI.
- **Safe development first** — Management listeners are loopback-only, and production networking mode is explicitly rejected.

<code>WG/1</code> and <code>WG-HS/1</code> are project-specific experimental formats and state machines; they **do not imply WireGuard compatibility**. Cryptographic capabilities use Go implementations of X25519, ChaCha20-Poly1305, BLAKE2s, and HKDF. WG does not invent low-level cryptographic primitives and has not received an independent security audit.

## Implemented Today

| Module | Safe-development capability |
| --- | --- |
| <code>internal/codec</code> | Bounded <code>WG/1</code> packet, TLV, and inner-frame parsing and serialization, with unit tests and fuzz entry points |
| <code>internal/crypto</code> | Standard primitives, canonical fingerprints, and high-level handshake/transport interfaces |
| <code>internal/handshake</code> | In-memory <code>WG-HS/1</code> development path for registered clients |
| <code>internal/session</code> | Client/server state machines, packet numbers, and replay protection |
| <code>internal/routing</code> | Domain, IP, and CIDR decisions using four routing states |
| <code>internal/privatedns</code> | Read-only resolver snapshot, generation isolation, and private TTL cache |
| <code>internal/controlapi</code> | Local management API with request-size, timeout, and concurrency limits |
| <code>cmd</code> / <code>ui</code> / <code>scripts</code> | Safe control core, five-page client UI, and real TCP/UDP proxy scripts |

The safe control-core components validate the architecture and management workflow. Real proxy traffic is carried by <code>wg-proxy</code>.

## Architecture

~~~text
Client UI (React, served by a Go host)
        │  http://127.0.0.1:4173
        ▼
wg-client-ui
        │  /api/v1
        ▼
wg-core client (loopback management API)
        ├── WG/1 + WG-HS/1
        ├── crypto + session
        ├── AUTO intelligent routing
        └── private DNS snapshot and cache

wg-core server (no UI, script-managed)
        └── safe mode records the configured data address only

UDP / TUN / system routes / firewall / NAT
        └── not connected yet
~~~

## Client UI

![WG client connection-page prototype](./docs/ui-prototypes/wg-client-01-connection.png)

The client contains five views: Connection, Intelligent Routing, Private DNS, Health & Updates, and First Pairing. More prototypes are available in [docs/ui-prototypes](./docs/ui-prototypes).

The Connection view is operational, not a mock. Put `server-cert.pem` and `token` (mode `0600`) in `~/.wg-client`, start `./bin/wg-client-ui`, then add or select a server IP, port (default `9518`), and TCP/UDP mode. The UI stores server profiles locally and starts the sibling `wg-proxy` binary on `127.0.0.1:47101` (TCP) and/or `127.0.0.1:47102` (UDP) without changing the system DNS.

## Requirements

- Go 1.26+
- Node.js 20+
- <code>make</code>

## Quick Start

~~~sh
git clone https://github.com/Aiweline/WG.git
cd WG
npm --prefix ui/client install
make build
~~~

Start the safe client core:

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core client \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47003 \
  --endpoint 203.0.113.10:9518
~~~

<code>203.0.113.10</code> is a TEST-NET documentation address. The current build records the endpoint but does not establish a real tunnel.

Start the client UI in another terminal:

~~~sh
./bin/wg-client-ui \
  --listen 127.0.0.1:4173 \
  --assets ui/client/dist \
  --core http://127.0.0.1:47003
~~~

Open [http://127.0.0.1:4173/](http://127.0.0.1:4173/).

Optional safe server core:

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core server \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47002 \
  --listen 0.0.0.0:9518
~~~

In safe mode, <code>--listen</code> is configuration data only and does not open a UDP socket.

## WG Scripts

For the real proxy data plane, build the binary and use the script switch:

~~~sh
make build
sudo WG_PROXY_BIN="$PWD/bin/wg-proxy" ./scripts/wg-server proxy install \
  --server-ip YOUR_PUBLIC_IP --listen :9518

./scripts/wg-client proxy start tcp \
  --server SERVER_IP:9518 --ca ./server-cert.pem --token-file ./token

./scripts/wg-client proxy start udp \
  --server SERVER_IP:9518 --target 1.1.1.1:53 --token-file ./token
~~~

> [!IMPORTANT]
The proxy installer enables <code>wg-proxy-tcp.service</code> and <code>wg-proxy-udp.service</code>. It never changes DNS, routes, NAT, or firewall rules.

## Repository Layout

~~~text
cmd/                    wg-core and wg-client-ui
internal/               protocol, session, routing, DNS, and control API
scripts/                wg-client and wg-server
ui/client/              client UI
docs/ui-prototypes/     multi-page prototypes
tests/                  cross-package and boundary tests
~~~

## Validation

~~~sh
go test ./cmd/... ./internal/... ./tests/...
go test -race ./cmd/... ./internal/... ./tests/...
go vet ./cmd/... ./internal/... ./tests/...
npm --prefix ui/client run build
sh -n scripts/wg-client
sh -n scripts/wg-server
~~~

## Required Before Production

- UDP transport, a real TUN data plane, IPv4/IPv6, MTU handling, and traffic-encryption integration.
- Atomic route transactions, least-privilege helpers, service isolation, firewall/NAT integration, and rollback.
- A complete private DNS socket, per-link resolver capture, and TTL refresh.
- Persistent client enrollment, a production key lifecycle, one-time enrollment, and RETRY state.
- Signed releases, supply-chain verification, packaging, cross-platform testing, and independent security audits.

## Contributing

Issues and pull requests are welcome. Keep safe development mode as the default, add tests for behavioral changes, and run all validation commands before submitting.

Changes to the protocol, cryptography, replay protection, routing, DNS, or system networking should document compatibility, security impact, and validation evidence.
