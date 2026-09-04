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
}
