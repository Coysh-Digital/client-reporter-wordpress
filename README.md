# Client Reporter Connector for WordPress

The companion WordPress plugin for [Client Reporter](https://github.com/coysh-digital/client-reporter) —
open-source, self-hosted client reporting for web agencies.

It exposes a small, **read-only** REST API that a Client Reporter installation pulls from to build
client reports. It never modifies your site, applies updates, or exposes secrets, files or the database.

## What it exposes

- WordPress / PHP versions, site name, URL and environment
- Active theme, plugin and theme counts
- Available core, plugin and theme updates (**reported, never applied**)
- User and administrator counts, basic Site Health
- WooCommerce sales for a date range (when WooCommerce is active): revenue, orders, average order
  value, items sold, refunds and top products

## Security model

Client Reporter always **pulls**; this plugin only ever responds. Every request is signed with
HMAC-SHA256 over `method + path + timestamp + nonce + body-hash` using a shared **connection code**.
The plugin rejects:

- unsigned or wrongly-signed requests,
- requests whose timestamp is outside a ±300s window (replay/timestamp validation),
- replayed nonces (cached for the window).

Rotate the connection code any time by generating a new one in Client Reporter and pasting it here.

## Installation

1. Install and activate this plugin on the WordPress site.
2. In Client Reporter, add the site as a **WordPress** integration and copy the connection code.
3. In WordPress: **Settings → Client Reporter**, paste the code, Save.
4. In Client Reporter, press **Save & verify**.

## Compatibility

Connector version `0.1.0`. Compatibility with Client Reporter releases is documented in the main
Client Reporter repository.

## License

MIT © 2026 Tim Coysh
