<?php
/**
 * A minimal settings screen: paste the connection code from Client Reporter.
 */

if (! defined('ABSPATH')) {
    exit;
}

class Client_Reporter_Admin
{
    public static function register_menu()
    {
        add_options_page(
            'Client Reporter',
            'Client Reporter',
            'manage_options',
            'client-reporter',
            array(__CLASS__, 'render_page')
        );
    }

    public static function register_settings()
    {
        register_setting('client_reporter', CLIENT_REPORTER_WP_SECRET_OPTION, array(
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default'           => '',
        ));
    }

    public static function render_page()
    {
        if (! current_user_can('manage_options')) {
            return;
        }

        $secret    = get_option(CLIENT_REPORTER_WP_SECRET_OPTION);
        $connected = ! empty($secret);
        ?>
        <div class="wrap">
            <h1>Client Reporter</h1>
            <p>Connect this site to your agency's Client Reporter installation. This connector is
               <strong>read-only</strong> — it never changes your site.</p>

            <p>Status:
                <?php if ($connected) : ?>
                    <span style="color:#3f7d54;font-weight:600;">Connection code saved</span>
                <?php else : ?>
                    <span style="color:#a4712a;font-weight:600;">Not configured</span>
                <?php endif; ?>
            </p>

            <form method="post" action="options.php">
                <?php settings_fields('client_reporter'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="cr_secret">Connection code</label></th>
                        <td>
                            <input name="<?php echo esc_attr(CLIENT_REPORTER_WP_SECRET_OPTION); ?>"
                                   id="cr_secret" type="text" class="regular-text"
                                   value="<?php echo esc_attr($secret); ?>"
                                   autocomplete="off" />
                            <p class="description">Paste the connection code shown in Client Reporter when you add this
                               WordPress site, then press Save. Return to Client Reporter and press “Save &amp; verify”.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button('Save connection code'); ?>
            </form>
        </div>
        <?php
    }
}
