# PdnsPilot

A web-based admin UI for [PowerDNS](https://www.powerdns.com/) built with Rust (Axum), SQLite, and MiniJinja templates.

> **Hobby/Research Project** — This is a personal experiment built 100% with [Claude Code](https://claude.ai/code), including the project name. 🙂 No maintenance guarantees, no support, no roadmap. Use at your own risk.

## What it does

- Manage zones and DNS records across multiple PowerDNS servers via the PowerDNS HTTP API
- User management with role-based access
- DNSSEC key management
- Zone templates
- Audit log
- Real-time metrics via WebSocket
- Auto-notify slave servers on record changes for Master zones
- Reverse zone management (IPv4 `in-addr.arpa` and IPv6 `ip6.arpa`) with automatic network ↔ ARPA name conversion

## Reverse zones

Reverse zones (`*.in-addr.arpa` for IPv4, `*.ip6.arpa` for IPv6) are managed on a dedicated **Reverse Zones** page, separate from forward zones.

Features:
- Auto-detect reverse zones imported from PowerDNS by their ARPA name
- Display the human-readable network (e.g. `192.168.1.0/24`) derived from the ARPA zone name
- Record editor pre-filtered to PTR-relevant types (PTR, NS, SOA, CNAME, TXT, NSEC, NSEC3, RRSIG, DNSKEY, …)
- Helper tool: enter an IP address or CIDR prefix and get the correct ARPA zone name / PTR record name

## Stack

- **Runtime**: Rust + Tokio
- **Web framework**: Axum 0.7
- **Database**: SQLite via SQLx
- **Templates**: MiniJinja
- **Auth**: Argon2 password hashing, cookie sessions

## Quick start with Docker

```bash
# Generate a secret key
export PDNSPILOT_SECRET_KEY=$(openssl rand -hex 32)
export PDNSPILOT_DEFAULT_ADMIN_PASSWORD=changeme

docker compose up -d
```

Browse to `http://localhost:8080`. Default admin login: `admin` / value of `PDNSPILOT_DEFAULT_ADMIN_PASSWORD`.

## Configuration

All config via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PDNSPILOT_SECRET_KEY` | *(required)* | Session signing key — set to a random secret |
| `PDNSPILOT_DATABASE_PATH` | `./data/pdnspilot.db` | SQLite database path |
| `PDNSPILOT_DEFAULT_ADMIN_PASSWORD` | `admin` | Initial admin password (change after first login) |
| `PDNSPILOT_SESSION_LIFETIME_HOURS` | `8` | Session duration in hours |
| `BIND_ADDR` | `0.0.0.0:8080` | Listen address |
| `RUST_LOG` | `pdnspilot=info` | Log filter |

## Build from source

Requires Rust stable and the `sqlx-cli` for offline query compilation:

```bash
cargo build --release
./target/release/pdnspilot
```

## Disclaimer

Not production-hardened. No security audit. No guarantee of correctness. This project exists to scratch a personal itch and explore Rust web development.
