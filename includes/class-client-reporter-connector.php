<?php
/**
 * The read-only REST connector: signed-request authentication and data
 * collection. Registered under the client-reporter/v1 namespace.
 */

if (! defined('ABSPATH')) {
    exit;
}

class Client_Reporter_Connector
{
    /**
     * Register the read-only REST routes. Every route is guarded by a signed
     * request check; none accept a request body or mutate anything.
     */
    public static function register_routes()
    {
        $args = array(
            'methods'             => 'GET',
            'permission_callback' => array(__CLASS__, 'authenticate'),
        );

        register_rest_route(CLIENT_REPORTER_WP_NAMESPACE, '/verify', array_merge($args, array(
            'callback' => array(__CLASS__, 'verify'),
        )));

        register_rest_route(CLIENT_REPORTER_WP_NAMESPACE, '/site', array_merge($args, array(
            'callback' => array(__CLASS__, 'site'),
        )));

        register_rest_route(CLIENT_REPORTER_WP_NAMESPACE, '/woocommerce', array_merge($args, array(
            'callback' => array(__CLASS__, 'woocommerce'),
            'args'     => array(
                'start' => array('sanitize_callback' => 'sanitize_text_field'),
                'end'   => array('sanitize_callback' => 'sanitize_text_field'),
            ),
        )));

        register_rest_route(CLIENT_REPORTER_WP_NAMESPACE, '/updates', array_merge($args, array(
            'callback' => array(__CLASS__, 'updates'),
            'args'     => array(
                'from' => array('sanitize_callback' => 'sanitize_text_field'),
                'to'   => array('sanitize_callback' => 'sanitize_text_field'),
            ),
        )));

        register_rest_route(CLIENT_REPORTER_WP_NAMESPACE, '/forms', array_merge($args, array(
            'callback' => array(__CLASS__, 'forms'),
            'args'     => array(
                'start' => array('sanitize_callback' => 'sanitize_text_field'),
                'end'   => array('sanitize_callback' => 'sanitize_text_field'),
            ),
        )));
    }

    /* --------------------------------------------------------------------- */
    /* Update history                                                        */
    /* --------------------------------------------------------------------- */

    /**
     * Record applied core/plugin/theme updates as WordPress performs them, so
     * the report can say what was updated and when. Appends to a capped log
     * option; never removes or modifies anything else.
     *
     * @param \WP_Upgrader $upgrader   The upgrader instance (unused).
     * @param array        $hook_extra Details of what was updated.
     */
    public static function record_updates($upgrader, $hook_extra)
    {
        if (! is_array($hook_extra) || (isset($hook_extra['action']) && 'update' !== $hook_extra['action'])) {
            return;
        }

        $type = isset($hook_extra['type']) ? $hook_extra['type'] : '';
        $now  = current_time('c');
        $entries = array();

        if ('plugin' === $type) {
            if (! function_exists('get_plugin_data')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $plugins = isset($hook_extra['plugins']) ? (array) $hook_extra['plugins'] : array();
            foreach ($plugins as $file) {
                $path = WP_PLUGIN_DIR . '/' . $file;
                $data = is_readable($path) ? get_plugin_data($path, false, false) : array();
                $entries[] = array(
                    'type'    => 'plugin',
                    'name'    => ! empty($data['Name']) ? $data['Name'] : $file,
                    'version' => isset($data['Version']) ? $data['Version'] : '',
                    'date'    => $now,
                );
            }
        } elseif ('theme' === $type) {
            $themes = isset($hook_extra['themes']) ? (array) $hook_extra['themes'] : array();
            foreach ($themes as $stylesheet) {
                $theme = wp_get_theme($stylesheet);
                $entries[] = array(
                    'type'    => 'theme',
                    'name'    => $theme->exists() ? $theme->get('Name') : $stylesheet,
                    'version' => $theme->exists() ? $theme->get('Version') : '',
                    'date'    => $now,
                );
            }
        } elseif ('core' === $type) {
            $entries[] = array(
                'type'    => 'core',
                'name'    => 'WordPress core',
                'version' => get_bloginfo('version'),
                'date'    => $now,
            );
        }

        if (empty($entries)) {
            return;
        }

        $log = get_option(CLIENT_REPORTER_WP_UPDATE_LOG, array());
        if (! is_array($log)) {
            $log = array();
        }

        $log = array_merge($log, $entries);

        // Keep the log bounded; the report only ever reads a recent window.
        if (count($log) > 250) {
            $log = array_slice($log, -250);
        }

        update_option(CLIENT_REPORTER_WP_UPDATE_LOG, $log, false);
    }

    /* --------------------------------------------------------------------- */
    /* Authentication                                                        */
    /* --------------------------------------------------------------------- */

    /**
     * Verify the HMAC signature, timestamp window and nonce (replay protection).
     *
     * @param WP_REST_Request $request
     * @return bool|WP_Error
     */
    public static function authenticate($request)
    {
        $secret = get_option(CLIENT_REPORTER_WP_SECRET_OPTION);

        if (empty($secret)) {
            return new WP_Error('client_reporter_not_configured', 'Connector not configured.', array('status' => 403));
        }

        $timestamp = $request->get_header('x-cr-timestamp');
        $nonce     = $request->get_header('x-cr-nonce');
        $signature = $request->get_header('x-cr-signature');

        if (empty($timestamp) || empty($nonce) || empty($signature)) {
            return new WP_Error('client_reporter_unsigned', 'Missing signature.', array('status' => 401));
        }

        // Timestamp/replay window.
        if (abs(time() - (int) $timestamp) > CLIENT_REPORTER_WP_TIMESTAMP_TOLERANCE) {
            return new WP_Error('client_reporter_stale', 'Request timestamp out of range.', array('status' => 401));
        }

        // Replay protection: reject a nonce we have already seen within the window.
        $nonce_key = 'cr_nonce_' . md5($nonce);
        if (get_transient($nonce_key)) {
            return new WP_Error('client_reporter_replay', 'Nonce already used.', array('status' => 401));
        }

        $path      = '/wp-json' . $request->get_route();
        $expected  = self::sign('GET', $path, $timestamp, $nonce, '', $secret);

        if (! hash_equals($expected, $signature)) {
            return new WP_Error('client_reporter_bad_signature', 'Invalid signature.', array('status' => 401));
        }

        set_transient($nonce_key, 1, CLIENT_REPORTER_WP_TIMESTAMP_TOLERANCE * 2);

        return true;
    }

    /**
     * Compute the request signature. MUST match Client Reporter's
     * SignedConnectorClient::sign().
     */
    public static function sign($method, $path, $timestamp, $nonce, $body, $secret)
    {
        $payload = implode("\n", array(
            strtoupper($method),
            $path,
            $timestamp,
            $nonce,
            hash('sha256', $body),
        ));

        return hash_hmac('sha256', $payload, $secret);
    }

    /* --------------------------------------------------------------------- */
    /* Endpoints                                                             */
    /* --------------------------------------------------------------------- */

    public static function verify()
    {
        return rest_ensure_response(array(
            'ok'                => true,
            'connector'         => 'wordpress',
            'version'           => CLIENT_REPORTER_WP_VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'woocommerce'       => self::woocommerce_active(),
            'gravity_forms'     => self::gravity_forms_active(),
            'ninja_forms'       => self::ninja_forms_active(),
        ));
    }

    public static function site()
    {
        if (! function_exists('get_plugin_updates')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
            require_once ABSPATH . 'wp-admin/includes/theme.php';
        }

        $plugin_updates = function_exists('get_plugin_updates') ? get_plugin_updates() : array();
        $theme_updates  = function_exists('get_theme_updates') ? get_theme_updates() : array();
        $core_updates   = function_exists('get_core_updates') ? get_core_updates() : array();

        $core_update_available = false;
        if (is_array($core_updates)) {
            foreach ($core_updates as $update) {
                if (isset($update->response) && 'upgrade' === $update->response) {
                    $core_update_available = true;
                    break;
                }
            }
        }

        $plugin_list = array();
        foreach ((array) $plugin_updates as $file => $plugin) {
            $plugin_list[] = array(
                'name'      => isset($plugin->Name) ? $plugin->Name : $file,
                'current'   => isset($plugin->Version) ? $plugin->Version : '',
                'available' => isset($plugin->update->new_version) ? $plugin->update->new_version : '',
            );
        }

        $theme_list = array();
        foreach ((array) $theme_updates as $stylesheet => $theme) {
            $theme_list[] = array(
                'name'      => is_object($theme) && method_exists($theme, 'get') ? $theme->get('Name') : $stylesheet,
                'available' => isset($theme->update['new_version']) ? $theme->update['new_version'] : '',
            );
        }

        $active_theme = wp_get_theme();
        $admins       = get_users(array('role' => 'administrator', 'fields' => 'ID'));

        return rest_ensure_response(array(
            'wordpress_version'  => get_bloginfo('version'),
            'php_version'        => phpversion(),
            'site_name'          => get_bloginfo('name'),
            'site_url'           => get_site_url(),
            'environment'        => function_exists('wp_get_environment_type') ? wp_get_environment_type() : 'production',
            'active_theme'       => $active_theme ? $active_theme->get('Name') : null,
            'core_update_available' => $core_update_available,
            'plugin_updates'     => count($plugin_list),
            'theme_updates'      => count($theme_list),
            'plugin_updates_list' => $plugin_list,
            'theme_updates_list' => $theme_list,
            'plugins_total'      => count((array) get_option('active_plugins', array())),
            'users'              => (int) count_users()['total_users'],
            'admins'             => count($admins),
            'site_health'        => $core_update_available || count($plugin_list) > 0 ? 'attention' : 'good',
        ));
    }

    /**
     * The applied-update history, optionally limited to a from/to date window.
     *
     * @param WP_REST_Request $request
     */
    public static function updates($request)
    {
        $log = get_option(CLIENT_REPORTER_WP_UPDATE_LOG, array());
        if (! is_array($log)) {
            $log = array();
        }

        $from = $request->get_param('from');
        $to   = $request->get_param('to');
        $from_ts = $from ? strtotime($from . ' 00:00:00') : null;
        $to_ts   = $to ? strtotime($to . ' 23:59:59') : null;

        $entries = array();
        $counts  = array('core' => 0, 'plugin' => 0, 'theme' => 0);

        foreach ($log as $entry) {
            $when = isset($entry['date']) ? strtotime($entry['date']) : false;
            if ($from_ts && (false === $when || $when < $from_ts)) {
                continue;
            }
            if ($to_ts && (false === $when || $when > $to_ts)) {
                continue;
            }

            $type = isset($entry['type']) ? $entry['type'] : '';
            if (isset($counts[$type])) {
                $counts[$type]++;
            }
            $entries[] = $entry;
        }

        return rest_ensure_response(array(
            'total'   => count($entries),
            'core'    => $counts['core'],
            'plugins' => $counts['plugin'],
            'themes'  => $counts['theme'],
            'entries' => array_values($entries),
        ));
    }

    public static function woocommerce($request)
    {
        if (! self::woocommerce_active()) {
            return rest_ensure_response(array('active' => false));
        }

        $start = $request->get_param('start') ? $request->get_param('start') . ' 00:00:00' : gmdate('Y-m-01 00:00:00');
        $end   = $request->get_param('end') ? $request->get_param('end') . ' 23:59:59' : gmdate('Y-m-t 23:59:59');

        $orders = wc_get_orders(array(
            'limit'        => -1,
            'status'       => array('wc-completed', 'wc-processing'),
            'date_created' => strtotime($start) . '...' . strtotime($end),
            'return'       => 'objects',
        ));

        $revenue   = 0.0;
        $items     = 0;
        $refunds   = 0.0;
        $products  = array();

        foreach ($orders as $order) {
            $revenue += (float) $order->get_total();
            $refunds += (float) $order->get_total_refunded();
            foreach ($order->get_items() as $item) {
                $qty   = (int) $item->get_quantity();
                $items += $qty;
                $name  = $item->get_name();
                if (! isset($products[$name])) {
                    $products[$name] = array('name' => $name, 'quantity' => 0, 'revenue' => 0.0);
                }
                $products[$name]['quantity'] += $qty;
                $products[$name]['revenue']  += (float) $item->get_total();
            }
        }

        usort($products, function ($a, $b) {
            return $b['revenue'] <=> $a['revenue'];
        });

        $order_count = count($orders);

        return rest_ensure_response(array(
            'active'              => true,
            'currency'            => get_woocommerce_currency(),
            'revenue'             => round($revenue, 2),
            'orders'              => $order_count,
            'average_order_value' => $order_count > 0 ? round($revenue / $order_count, 2) : 0,
            'items_sold'          => $items,
            'refunds'             => round($refunds, 2),
            'top_products'        => array_slice(array_values($products), 0, 5),
        ));
    }

    private static function woocommerce_active()
    {
        return class_exists('WooCommerce');
    }

    /* --------------------------------------------------------------------- */
    /* Form submissions (Gravity Forms / Ninja Forms)                        */
    /* --------------------------------------------------------------------- */

    /**
     * Form-submission counts for the reporting period from Gravity Forms and/or
     * Ninja Forms, if either is active. Returns a per-form breakdown and a
     * zero-filled daily series, so the report can chart responses over time.
     *
     * @param WP_REST_Request $request
     */
    public static function forms($request)
    {
        $gravity = self::gravity_forms_active();
        $ninja   = self::ninja_forms_active();

        if (! $gravity && ! $ninja) {
            return rest_ensure_response(array('active' => false));
        }

        $start = $request->get_param('start') ? $request->get_param('start') : gmdate('Y-m-01');
        $end   = $request->get_param('end') ? $request->get_param('end') : gmdate('Y-m-t');

        // Zero-filled daily buckets across the whole window, so quiet days are
        // still charted as zero rather than dropped.
        $days     = array();
        $start_ts = strtotime($start . ' 00:00:00');
        $end_ts   = strtotime($end . ' 23:59:59');
        for ($t = $start_ts; $t !== false && $t <= $end_ts; $t += DAY_IN_SECONDS) {
            $days[gmdate('Y-m-d', $t)] = 0;
        }

        $forms     = array();
        $providers = array();

        if ($gravity) {
            $providers[] = 'gravity';
            self::collect_gravity_forms($start, $end, $days, $forms);
        }

        if ($ninja) {
            $providers[] = 'ninja';
            self::collect_ninja_forms($start, $end, $days, $forms);
        }

        usort($forms, function ($a, $b) {
            return $b['submissions'] <=> $a['submissions'];
        });

        $timeseries = array();
        $total      = 0;
        foreach ($days as $date => $count) {
            $timeseries[] = array('date' => $date, 'value' => (int) $count);
            $total += (int) $count;
        }

        return rest_ensure_response(array(
            'active'     => true,
            'providers'  => $providers,
            'total'      => (int) $total,
            'forms'      => array_values($forms),
            'timeseries' => $timeseries,
        ));
    }

    private static function gravity_forms_active()
    {
        return class_exists('GFAPI');
    }

    private static function ninja_forms_active()
    {
        return function_exists('Ninja_Forms');
    }

    /**
     * Add Gravity Forms submissions to the daily buckets and per-form totals.
     * One grouped query over the entry table (GF 2.3+ `gf_entry`, older
     * `rg_lead`); titles come from GFAPI. Read-only.
     *
     * @param array $days  Daily buckets, keyed Y-m-d, passed by reference.
     * @param array $forms Per-form rows, keyed "gravity:<id>", passed by reference.
     */
    private static function collect_gravity_forms($start, $end, &$days, &$forms)
    {
        global $wpdb;

        $table = self::table_name($wpdb->prefix . 'gf_entry');
        $date_column = 'date_created';
        if ($table === null) {
            $table = self::table_name($wpdb->prefix . 'rg_lead');
        }
        if ($table === null) {
            return;
        }

        $titles = array();
        foreach (GFAPI::get_forms() as $form) {
            $titles[(string) $form['id']] = $form['title'];
        }

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT form_id, DATE({$date_column}) AS day, COUNT(*) AS total"
            . " FROM {$table}"
            . " WHERE status = 'active' AND {$date_column} BETWEEN %s AND %s"
            . " GROUP BY form_id, DATE({$date_column})",
            $start . ' 00:00:00',
            $end . ' 23:59:59'
        ));

        foreach ((array) $rows as $row) {
            $count = (int) $row->total;
            if (isset($days[$row->day])) {
                $days[$row->day] += $count;
            }

            $key = 'gravity:' . $row->form_id;
            if (! isset($forms[$key])) {
                $forms[$key] = array(
                    'name'        => isset($titles[(string) $row->form_id]) ? $titles[(string) $row->form_id] : ('Form #' . $row->form_id),
                    'source'      => 'Gravity Forms',
                    'submissions' => 0,
                );
            }
            $forms[$key]['submissions'] += $count;
        }
    }

    /**
     * Add Ninja Forms submissions to the daily buckets and per-form totals.
     * Ninja Forms 3 stores each submission as an `nf_sub` post with the form id
     * in `_form_id` postmeta; titles come from the `nf3_forms` table. Read-only.
     *
     * @param array $days  Daily buckets, keyed Y-m-d, passed by reference.
     * @param array $forms Per-form rows, keyed "ninja:<id>", passed by reference.
     */
    private static function collect_ninja_forms($start, $end, &$days, &$forms)
    {
        global $wpdb;

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT pm.meta_value AS form_id, DATE(p.post_date) AS day, COUNT(*) AS total"
            . " FROM {$wpdb->posts} p"
            . " INNER JOIN {$wpdb->postmeta} pm ON pm.post_id = p.ID AND pm.meta_key = '_form_id'"
            . " WHERE p.post_type = 'nf_sub' AND p.post_status = 'publish'"
            . " AND p.post_date BETWEEN %s AND %s"
            . " GROUP BY pm.meta_value, DATE(p.post_date)",
            $start . ' 00:00:00',
            $end . ' 23:59:59'
        ));

        if (empty($rows)) {
            return;
        }

        $titles     = array();
        $forms_table = self::table_name($wpdb->prefix . 'nf3_forms');
        if ($forms_table !== null) {
            foreach ((array) $wpdb->get_results("SELECT id, title FROM {$forms_table}") as $form) {
                $titles[(string) $form->id] = $form->title;
            }
        }

        foreach ($rows as $row) {
            $count = (int) $row->total;
            if (isset($days[$row->day])) {
                $days[$row->day] += $count;
            }

            $key = 'ninja:' . $row->form_id;
            if (! isset($forms[$key])) {
                $forms[$key] = array(
                    'name'        => isset($titles[(string) $row->form_id]) ? $titles[(string) $row->form_id] : ('Form #' . $row->form_id),
                    'source'      => 'Ninja Forms',
                    'submissions' => 0,
                );
            }
            $forms[$key]['submissions'] += $count;
        }
    }

    /**
     * Return the exact table name if it exists, else null — so a grouped query
     * is never run against a missing table.
     */
    private static function table_name($table)
    {
        global $wpdb;

        $found = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));

        return $found === $table ? $table : null;
    }
}
