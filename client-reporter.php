<?php
/**
 * Plugin Name:       Client Reporter Connector
 * Plugin URI:        https://github.com/coysh-digital/client-reporter-wordpress
 * Description:       Securely exposes read-only WordPress status, update and WooCommerce data to a Client Reporter installation. Never modifies your site.
 * Version:           0.2.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Tim Coysh
 * License:           MIT
 * Text Domain:       client-reporter
 *
 * Companion to Client Reporter (https://github.com/coysh-digital/client-reporter).
 * This plugin only ever READS and returns data. It performs no updates and
 * exposes no secrets, arbitrary files or database access.
 */

if (! defined('ABSPATH')) {
    exit;
}

define('CLIENT_REPORTER_WP_VERSION', '0.2.0');
define('CLIENT_REPORTER_WP_NAMESPACE', 'client-reporter/v1');
define('CLIENT_REPORTER_WP_SECRET_OPTION', 'client_reporter_secret');
define('CLIENT_REPORTER_WP_UPDATE_LOG', 'client_reporter_update_log');
define('CLIENT_REPORTER_WP_TIMESTAMP_TOLERANCE', 300); // seconds

require_once __DIR__ . '/includes/class-client-reporter-connector.php';
require_once __DIR__ . '/includes/class-client-reporter-admin.php';

add_action('rest_api_init', array('Client_Reporter_Connector', 'register_routes'));
add_action('admin_menu', array('Client_Reporter_Admin', 'register_menu'));
add_action('admin_init', array('Client_Reporter_Admin', 'register_settings'));

// Record applied core/plugin/theme updates so the report can show what changed.
add_action('upgrader_process_complete', array('Client_Reporter_Connector', 'record_updates'), 10, 2);
