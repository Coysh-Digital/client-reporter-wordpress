=== Client Reporter Connector ===
Contributors: timcoysh
Tags: reporting, agency, uptime, woocommerce, gravity forms, ninja forms
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 7.4
Stable tag: 0.3.0
License: MIT

Securely exposes read-only WordPress status, updates, WooCommerce and form-submission data to a self-hosted Client Reporter installation.

== Description ==

This is the companion plugin for **Client Reporter** (https://github.com/coysh-digital/client-reporter),
the open-source, self-hosted client reporting tool for web agencies.

The plugin exposes a small, **read-only** REST API that Client Reporter pulls from on a schedule to
build client reports. It is deliberately narrow:

* It only ever READS and returns data.
* It performs no updates and installs nothing.
* It exposes no secrets, `.env` contents, arbitrary files or database access.

= Data exposed =

* WordPress, PHP and site name / URL / environment
* Active theme and installed plugin/theme counts
* Available core, plugin and theme updates (reported, never applied)
* Number of users and administrators
* Basic Site Health status
* WooCommerce sales for a date range (revenue, orders, average order value, items sold, refunds, top products) when WooCommerce is active

= Security =

Every request from Client Reporter is signed with HMAC-SHA256 over the method, path, timestamp and a
nonce, using a shared connection code. The plugin rejects unsigned requests, stale timestamps
(replay/timestamp validation) and replayed nonces.

== Installation ==

1. Install and activate the plugin.
2. In Client Reporter, add this website as a WordPress integration and copy the connection code.
3. In WordPress, go to Settings → Client Reporter and paste the connection code, then Save.
4. Back in Client Reporter, press “Save & verify”.

== Changelog ==

= 0.3.0 =
* Added a read-only forms endpoint that reports Gravity Forms and Ninja Forms submission counts for the reporting period, with a per-form breakdown and a daily series.

= 0.2.0 =
* Record and expose applied update history, so reports can show what was updated and when.

= 0.1.0 =
* Initial release: signed read-only connector for site status, updates and WooCommerce.
