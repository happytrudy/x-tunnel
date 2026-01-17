# x-tunnel-client-rust

A Rust translation of the x-tunnel SOCKS5 proxy client.

## Features

- SOCKS5 proxy listener
- WebSocket connection to server
- Config loading from YAML or CLI
- DNS over HTTPS for ECH key fetching (ECH not implemented due to lack of support in rustls)

## Note

ECH (Encrypted Client Hello) is not implemented in this Rust version because the rustls library does not currently support it. The code falls back to standard TLS 1.3.

## Build

Ensure Rust is installed (https://rustup.rs/).

```bash
cargo build --release
```

## Run

```bash
./target/release/x-tunnel-client --help
```

Example:

```bash
./target/release/x-tunnel-client -l socks5://127.0.0.1:1080 -f wss://example.com/ws
```

## Config File

Create a `config.yaml`:

```yaml
listen: "socks5://127.0.0.1:1080"
forward: "wss://example.com/ws"
token: "your_token"
connection_num: 3
insecure: false
dns_server: "https://doh.pub/dns-query"
ech_domain: "cloudflare-ech.com"
fallback: true
```

Then run:

```bash
./target/release/x-tunnel-client --config config.yaml
```