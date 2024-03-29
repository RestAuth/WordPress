<?php
class RestAuthOptionsPage {
    var $option_prefix = 'restauth';
    var $plugin;
    var $group;
    var $page;
    var $options;
    var $title;

    function RestAuthOptionsPage($plugin, $group, $page, $options, $title = 'RestAuth') {
        $this->plugin = $plugin;
        $this->group = $group;
        $this->page = $page;
        $this->options = $options;
        $this->title = $title;

        add_action('admin_init', array($this, 'register_options'));
        add_action('admin_menu', array($this, 'add_options_page'));
    }

    /*
     * Register the options for this plugin so they can be displayed and updated below.
     */
    function register_options() {
        register_setting($this->group, $this->group,
            array($this, 'sanitize_settings'));

        $section = 'restauth_server';
        add_settings_section($section, 'RestAuth server options',
            array($this, '_display_options_section'), $this->page);
        add_settings_field($prefix . '_server', 'Server',
            array($this, '_display_option_server'), $this->page,
            $section, array('label_for' => $prefix . '_server'));
        add_settings_field($prefix . '_user', 'User',
            array($this, '_display_option_user'), $this->page,
            $section, array('label_for' => $prefix . '_user'));
        add_settings_field($prefix . '_password', 'Password',
            array($this, '_display_option_password'), $this->page,
            $section, array('label_for' => $prefix . '_password'));

        $section = 'restauth_sync';
        add_settings_section($section, 'RestAuth synchronization options',
            array($this, '_display_options_section'), $this->page);
        add_settings_field($prefix . '_allow_wp_auth', 'Fallback to built in authentication system',
            array($this, '_display_option_allow_wp_auth'), $this->page,
            $section, array('label_for' => $prefix . '_auto_create_user'));
        add_settings_field($prefix . '_auto_create_user', 'Create local users',
            array($this, '_display_option_auto_create_user'), $this->page,
            $section, array('label_for' => $prefix . '_auto_create_user'));
        add_settings_field($prefix . '_auto_sync_groups', 'Synchronize groups',
            array($this, '_display_option_auto_sync_groups'), $this->page,
            $section, array('label_for' => $prefix . '_auto_sync_groups'));

        $section = 'restauth_props';
        add_settings_section($section, 'User settings synchronization',
            array($this, '_display_options_section'), $this->page);
        add_settings_field($prefix . '_auto_sync_props', 'Synchronize user settings',
            array($this, '_display_option_auto_sync_props'), $this->page,
            $section, array('label_for' => $prefix . '_auto_sync_props'));
        add_settings_field($prefix . '_global_mappings', 'Global mappings',
            array($this, '_display_option_global_mappings'), $this->page,
            $section, array('label_for' => $prefix . '_gloal_mappings'));
        add_settings_field($prefix . '_local_mappings', 'Local mappings',
            array($this, '_display_option_local_mappings'), $this->page,
            $section, array('label_for' => $prefix . '_local_mappings'));
        add_settings_field($prefix . '_blacklist', 'Blacklist',
            array($this, '_display_option_blacklist'), $this->page,
            $section, array('label_for' => $prefix . '_blacklist'));
    }

    /*
     * Set the database version on saving the options.
     *
     * Called when saving settings (only on POST).
     */
    function sanitize_settings($input) {
        $output = $input;
        $output['db_version'] = $this->plugin->db_version;
        $output['server'] = isset($input['server']) ? $input['server'] : 'http://localhost';
        $output['allow_wp_auth'] = isset($input['allow_wp_auth']) ? (bool) $input['allow_wp_auth'] : false;
        $output['auto_create_user'] = isset($input['auto_create_user']) ? (bool) $input['auto_create_user'] : false;
        $output['auto_sync_groups'] = isset($input['auto_sync_groups']) ? (bool) $input['auto_sync_groups'] : false;
        $output['auto_sync_props'] = isset($input['auto_sync_props']) ? (bool) $input['auto_sync_props'] : false;
        $output['global_mappings'] = isset($input['global_mappings']) ? $input['global_mappings'] : '';
        $output['local_mappings'] = isset($input['local_mappings']) ? $input['local_mappings'] : '';
        $output['blacklist'] = isset($input['blacklist']) ? $input['blacklist'] : '';

        return $output;
    }

    /*
     * Add an options page for this plugin.
     */
    function add_options_page() {
        add_options_page($this->title, $this->title, 'manage_options', $this->page, array($this, '_display_options_page'));
    }

    /*
     * Display the options for this plugin.
     */
    function _display_options_page() {
        if (! current_user_can('manage_options')) {
            wp_die(__('You do not have sufficient permissions to access this page.'));
        }
?>
<div class="wrap">
  <h2>RestAuth Options</h2>
  <form action="options.php" method="post">
    <?php settings_errors(); ?>
    <?php settings_fields($this->group); ?>
    <?php do_settings_sections($this->page); ?>
    <p class="submit">
      <input type="submit" name="Submit" value="<?php esc_attr_e('Save Changes'); ?>" class="button-primary" />
    </p>
  </form>
</div>
<?php
    }

    /*
     * Display explanatory text for the main options section.
     */
    function _display_options_section() {
    }

    function _display_option_server() {
        $server = $this->options['server'];
        $this->_display_input_text_field('server', $server);
?>
Default is <code>http://localhost</code>, the RestAuth server used in this installation.
<?php
    }

    function _display_option_user() {
        $user = $this->options['user'];
        $this->_display_input_text_field('user', $user);
?>
The username used to authenticate with the RestAuth server.
<?php
    }

    function _display_option_password() {
        $password = $this->options['password'];
        $this->_display_input_text_field('password', $password, 75, true);
?>
The password used to authenticate with the RestAuth server.
<?php
    }

    /*
     * Display the WordPress authentication checkbox.
     */
    function _display_option_auto_sync_groups() {
        $auto_sync_groups = $this->options['auto_sync_groups'];
        $this->_display_checkbox_field('auto_sync_groups', $auto_sync_groups);
?>
Should groups be synchronized from the RestAuth server?
<?php
    }

    /*
     * Display the WordPress authentication checkbox.
     */
    function _display_option_auto_sync_props() {
        $auto_sync_props = $this->options['auto_sync_props'];
        $this->_display_checkbox_field('auto_sync_props', $auto_sync_props);
?>
Should user settings be synchronized from the RestAuth server?
<?php
    }

    /*
     * Display the WordPress authentication checkbox.
     */
    function _display_option_allow_wp_auth() {
        $allow_wp_auth = $this->options['allow_wp_auth'];
        $this->_display_checkbox_field('allow_wp_auth', $allow_wp_auth);
?>
Should the plugin fallback to WordPress authentication if the RestAuth server does not work?
<?php
    }

    /*
     * Display the automatically create accounts checkbox.
     */
    function _display_option_auto_create_user() {
        $auto_create_user = $this->options['auto_create_user'];
        $this->_display_checkbox_field('auto_create_user', $auto_create_user);
?>
Should a new user be created automatically if not already in the WordPress database?<br />
If
Created users will obtain the role defined under &quot;New User Default Role&quot; on the <a href="options-general.php">General Options</a> page.
<?php
    }

    function _display_option_global_mappings() {
        $global_mappings = $this->options['global_mappings'];
        $this->_display_textarea_field('global_mappings', $global_mappings);
?>
<p>Local user settings that should be saved to the RestAuth service. Settings
added here are "global", meaning they can easily be used by other systems
accessing RestAuth.</p>
<p>Add one per line, with the local setting name and the name used in RestAuth,
separated by a <code>|</code>. The default is usually fine, unless you have
extensions that add additional user settings that should also be saved in
RestAuth.</p>
<?php
    }

    function _display_option_local_mappings() {
        $local_mappings = $this->options['local_mappings'];
        $this->_display_textarea_field('local_mappings', $local_mappings);
?>
If a user setting only makes sense in a WordPress context, you may add it here
instead of at <code>global mappings</code>. These settings will be added to the
RestAuth server with a prefix, so only WordPress installations should use it.
<?php
    }

    function _display_option_blacklist() {
        $blacklist = $this->options['blacklist'];
        $this->_display_textarea_field('blacklist', $blacklist);
?>
A blacklist of options that will never be synchronized to RestAuth. Add one per
line. Note that <code>user_pass</code> (which is the users password hash) will
*never* be synced, no matter what you set here.
<?php
    }

    /*
     * Display a text input field.
     */
    function _display_input_text_field($name, $value, $size = 75, $password = false) {
        $type = $password ? 'password' : 'text';
?>
<input type="<?php echo $type ?>" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>" value="<?php echo htmlspecialchars($value) ?>" size="<?php echo htmlspecialchars($size); ?>" /><br />
<?php
    }

    /*
     * Display a textarea field.
     */
    function _display_textarea_field($name, $value, $cols = 75, $rows=5) {
?>
<textarea
        name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]"
        id="http_authentcation_<?php echo htmlspecialchars($name); ?>"
        rows="<?php echo $rows; ?>" cols="<?php echo $cols; ?>"><?php echo $value ?></textarea>
<br />
<?php
    }

    /*
     * Display a checkbox field.
     */
    function _display_checkbox_field($name, $value) {
?>
<input type="checkbox" name="<?php echo htmlspecialchars($this->group); ?>[<?php echo htmlspecialchars($name); ?>]" id="http_authentication_<?php echo htmlspecialchars($name); ?>"<?php if ($value) echo ' checked="checked"' ?> value="1" /><br />
<?php
    }
}
?>
