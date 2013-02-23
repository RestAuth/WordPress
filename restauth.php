<?php
/*
Plugin Name: RestAuth
Plugin URI: https://restauth.net/wiki/WordPress
Description: RestAuth authentication
Version: 0.1
Author: Mathias Ertl
Author URI: https://er.tl
License: GPL2
*/

/*  Copyright 2012  Mathias Ertl  (email : mati@restauth.net)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

require_once('RestAuth/restauth.php');
require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'options-page.php');

class RestAuthPlugin {
    private $conn;
    private $usercache = array();
    private $_global_mappings;
    private $_local_mappings;
    private $_blacklist;

    private $_normal_properties = array(
        'user_login', 'user_pass', 'user_email', 'user_url', 'user_nicename',
        'display_name', 'user_registered');

    private $option_name = 'restauth_options';
    var $db_version = 1;

    function __construct() {
        $this->options = get_option($this->option_name);

        if (is_admin()) {
            $options_page = new RestAuthOptionsPage($this, $this->option_name, __FILE__, $this->options);
            add_action('admin_init', array($this, 'admin_init'));
        }

        // pre-user registration:
        add_action('register_post', array($this, 'register_post'), 20, 3);

        // user registration:
        add_action('user_register', array($this, 'user_register'));

        // update the redirect after registration:
        add_filter('registration_redirect', array($this, 'registration_redirect'));
        add_filter('login_redirect', array($this, 'login_redirect'));

        // attempt to modify registration form:
        if(isset($_GET['action']) && $_GET['action'] == 'register'){
            add_action('register_form', array(&$this, 'register_form'));
            add_filter('gettext', array(&$this, 'remove_email_notification_msg'));
        }

        // authentication
        add_filter('authenticate', array($this, 'authenticate'), 20, 3);

        // setting a new password:
        add_action('check_passwords', array($this, 'check_passwords'), 20, 3);

        // load profile_data:
        // Called when viewing your own or someone elses profile
        add_action('personal_options', array($this, 'personal_options'), 20, 2);
        // load someone elses profile (TODO: really?):
//        add_action('edit_user_profile', array($this, 'personal_options'), 20, 2);

        // update own personal options
        add_action('profile_update', array($this, 'profile_update'), 20, 2);

        // update someone elses profile (admins) (TODO: really?:
        //add_action('edit_user_profile_update',
    }

    private function _get_conn() {
        if (is_null($this->conn)) {
            $this->conn = new RestAuthConnection(
                $this->options['server'], $this->options['user'],
                $this->options['password']);
        }
        return $this->conn;
    }

    public function admin_init() {
        if ($this->options === false || ! isset($this->options['db_version']) || $this->options['db_version'] < $this->db_version) {
            print('doing upgrade:<br>');
            if (! is_array($this->options)) {
                $this->options = array();
            }

            $current_db_version = isset($this->options['db_version']) ? $this->options['db_version'] : 0;
            $this->upgrade($current_db_version);
            $this->options['db_version'] = $this->db_version;
            update_option($this->option_name, $this->options);
        }
    }

    public function upgrade($current_db_version) {
        $default_options = array(
            'server' => 'http://localhost',
            'user' => '',
            'password' => '',
            'allow_wp_auth' => true,
            'auto_create_user' => true,
            'auto_sync_groups' => true,
            'auto_sync_props' => true,
            'global_mappings' => 'first_name|first name
last_name|last name
user_email|email
user_url|url
aim
yim
jabber|jid',
            'local_mappings' => 'nickname
display_name|display name
description',
            'blacklist' => 'user_pass',
        );
        // do nothing so far...
        if ($current_db_version < 1) {
        }
    }

    /**
     * Modify the registration form.
     *
     * Adds the password fields in the registration form.
     *
     * Called:
     * - GET wp-login.php?action=register - View registration form
     */
    public function register_form() {
        error_log('register_form');
    ?>
        <p>
            <label for="password">Password<br/>
                <input id="password" class="input" type="password" tabindex="30" size="25" value="" name="password" />
            </label>
        </p>
        <p>
            <label for="repeat_password">Repeat password<br/>
                <input id="repeat_password" class="input" type="password" tabindex="40" size="25" value="" name="repeat_password" />
            </label>
        </p>
        <?php
    }

    /**
     * Set the redirect url upon registration.
     *
     * Called:
     * - GET wp-login.php?action=register - View registration form
     */
    public function registration_redirect($redirect) {
        if ($redirect === "") {
            return site_url('wp-login.php');
        } else {
            return $redirect;
        }
    }

    /**
     * Set the global user_login variable if $_GET['user'] is set.
     *
     * This prefills the login-form with a username, if the appropriate GET
     * variable is set.
     *
     * WARNING: This is of course a disgusting misuse of this hook!
     *
     * NOTE: This function is currently unused, because the redirect url is
     *      computed BEFORE the user actually enters any data.
     *
     * Called:
     * - GET wp-login.php - Login a user
     */
    public function login_redirect($redirect) {
        global $user_login;

        if (!empty($_GET['user'])) {
            $user_login = $_GET['user'];
        }

        return $redirect;
    }

    /**
     * Verify that a user does not exist so far.
     *
     * Called:
     * - POST wp-login.php?action=register - Register a new user
     */
    public function register_post($user_login, $user_email, $errors) {
        error_log('register_post');
        if ( $_POST['password'] !== $_POST['repeat_password'] ) {
            $errors->add('passwords_not_matched', "<strong>ERROR</strong>: Passwords must match");
        }
        if ( strlen( $_POST['password'] ) < 8 ) {
            $errors->add('password_too_short', "<strong>ERROR</strong>: Passwords must be at least eight characters long");
        }

        // only call RestAuth if local check didn't fail already:
        if (! in_array('username_exists', $errors->get_error_codes())) {
            $conn = $this->_get_conn();
            try {
                RestAuthUser::get($conn, $user_login);
                // user already exists - we cannot register:
                $errors->add('username_exists',
                    '<strong>ERROR</strong>: This username is already registered, please choose another one.');
            } catch (RestAuthResourceNotFound $e) {
                // user doesn't exist - what we wanted to make sure
            }
        }
    }

    /**
     * Register a new user.
     *
     * This function creates a user in RestAuth and sets any properties.
     *
     * If allow_wp_auth is set, updates the locally stored hash (since the
     * current hash is for the auto-generated one), otherwise we set the
     * user_pass field to an empty value.
     *
     * Called:
     * - POST wp-login.php?action=register - Register a new user
     *
     * @see: wp_insert_user in wp-includes/user.php.
     */
    public function user_register($userid) {
        global $wpdb;

        $user = get_user_by('id', $userid);
        $conn = $this->_get_conn();

        $password = $_POST['password'];

        $properties = array();
        foreach ($this->get_global_mappings() as $key => $ra_key) {
            if (isset($user->$key) && !empty($user->$key)) {
                $properties[$ra_key] = $user->$key;
            }
        }
        foreach ($this->get_local_mappings() as $key => $ra_key) {
            if (isset($user->$key) && !empty($user->$key)) {
                $properties['wordpress ' . $ra_key] = $user->$key;
            }
        }

        $ra_user = RestAuthUser::create(
            $conn, $user->user_login, $password, $properties);
        $this->usercache[$user->user_login] = $ra_user;

        // store password locally if allow_wp_auth or empty string otherwise.
        // If we don't do this, the randomly generated password stays in the
        // database.
        $userdata = array();
        if ($this->options['allow_wp_auth']) {
            $userdata['user_pass'] = wp_hash_password($password);
        } else {
            $userdata['user_pass'] = '';
        }
        $wpdb->update($wpdb->users, $userdata, array('ID' => $userid));
    }

    /**
     * Remove the note that a password will be emailed during registration.
     */
    public function remove_email_notification_msg($text) {
        if ($text == 'A password will be e-mailed to you.') {
            return '';
        }
        return $text;
    }

    /**
     * Actually authenticate the user.
     */
    public function authenticate($user, $username, $password) {
        error_log("authentice(" . get_class($user) . ", $username, $password)");
        if ($_SERVER['REQUEST_METHOD'] != 'POST') {
            return $user;
        }

        $ra_user = $this->_get_ra_user($username);

        if ($ra_user->verifyPassword($password)) {
            $user = get_user_by('login', $username);
            if ($user) {
                $this->_update_user($user);
                return $user;
            } elseif (!$user && $this->options['auto_create_user']) {
                return $this->_create_user($username, $password);
            }
        }
        return null;
    }

    /**
     * Set a new password.
     *
     * @todo This also interacts with creating new passwords.
     */
    function check_passwords($username, $pass1, $pass2) {
        error_log("check_passwords '$username', '$pass1', '$pass2'");
        if (strlen($pass1) > 0 && strcmp($pass1, $pass2) === 0) {
            $ra_user = $this->_get_ra_user($username);
            $ra_user->setPassword($pass1);
        }
    }

    /**
     * Update local profile before viewing it.
     *
     * @param $user: WP_User
     *
     * Called:
     * - GET wp-admin/profile.php - View your own profile
     * - GET wp-admin/user-edit.php - View "Edit User" (view other users profile)
     *
     * @todo: update $user->user_registered information
     */
    public function personal_options($user) {
        error_log("personal_options");
        $this->_update_user($user);
    }

    /**
     * Helper function to decide if a property should be update or removed.
     */
    private function _handle_prop($user, $key, $ra_key, $ra_props,
        &$set_props, &$rm_props)
    {
        // if set and different to old prop, set
        if (is_string($user->$key) && strlen($user->$key) > 0) {
            if (!array_key_exists($ra_key, $ra_props)
                || $ra_props[$ra_key] != $user->$key)
            {
                $set_props[$ra_key] = $user->$key;
            }
        } elseif(array_key_exists($ra_key, $ra_props)) {
            $rm_props[] = $ra_key;
        }
    }

    /**
     * A mapping defining how local user properties map to RestAuth props.
     */
    private function get_global_mappings() {
        if (is_array($this->_global_mappings)) {
            return $this->_global_mappings;
        }

        $local_mappings = $this->get_local_mappings();
        $blacklist = $this->get_blacklist();

        $this->_global_mappings = array();
        foreach (explode("\n", $this->options['global_mappings']) as $line) {
            $trimmed = trim($line);
            if (strpos($trimmed, '|') === false) {
                $local = $trimmed;
                $remote = $trimmed;
            } else {
                list($local, $remote) = explode('|', $trimmed);
            }
            if (!array_key_exists($local, $local_mappings)
                && !in_array($local, $blacklist))
            {
                $this->_global_mappings[$local] = $remote;
            }
        }
        return $this->_global_mappings;
    }

    /**
     * A mapping defining how local user properties map to RestAuth props.
     */
    private function get_local_mappings() {
        if (is_array($this->_local_mappings)) {
            return $this->_local_mappings;
        }

        $blacklist = $this->get_blacklist();

        $this->_local_mappings = array();
        foreach (explode("\n", $this->options['local_mappings']) as $line) {
            $trimmed = trim($line);
            if (strpos($trimmed, '|') === false) {
                $local = $trimmed;
                $remote = $trimmed;
            } else {
                list($local, $remote) = explode('|', $trimmed);
            }
            if (!in_array($local, $blacklist)) {
                $this->_local_mappings[$local] = $remote;
            }
        }
        return $this->_local_mappings;
    }

    /**
     * A list of properties that should never be synced to RestAuth.
     */
    private function get_blacklist() {
        if (is_array($this->_blacklist)) {
            return $this->_blacklist;
        }

        $this->blacklist = array();
        foreach (explode("\n", $this->options['blacklist']) as $line) {
            $this->_blacklist[] = trim($line);
        }

        if (!in_array('user-pass', $this->blacklist)) {
            $this->_blacklist[] = 'user_pass';
        }

        return $this->_blacklist;
    }

    /**
     * Called when updating a profile.
     *
     * @todo: this hook also receives group-information.
     */
    public function profile_update($userid, $old_data) {
        error_log('profile_update');
        $user = get_userdata($userid);
        $ra_user = $this->_get_ra_user($user->user_login);
        $ra_props = $ra_user->getProperties();

        $ra_set_props = array();
        $ra_rm_props = array();

        foreach ($this->get_global_mappings() as $key => $ra_key) {
            $this->_handle_prop($user, $key, $ra_key, $ra_props,
                $ra_set_props, $ra_rm_props);
        }
        foreach ($this->get_local_mappings() as $key => $ra_key) {
            $ra_key = 'wordpress ' . $ra_key;
            $this->_handle_prop($user, $key, $ra_key, $ra_props,
                $ra_set_props, $ra_rm_props);
        }

        if (count($ra_set_props) > 0) {
            $ra_user->setProperties($ra_set_props);
        }
        if (count($ra_rm_props) > 0) {
            foreach ($ra_rm_props as $prop_name) {
                $ra_user->removeProperty($prop_name);
            }
        }
    }

    /**
     * Create a new user in the local database.
     *
     * @todo get roles from restauth service
     */
    private function _create_user($username, $password) {
        error_log("_create_user '$username'");
        global $wpdb;

        $userdata = array(
            'user_login' => $username,
            'user_pass' => '',
        );
        if ($this->options['allow_wp_auth']) {
            $userdata['user_pass'] = wp_hash_password($password);
        }

        $userdata = $this->_get_updated_userdata($userdata);

        // insert normal user data (directly in the wp_users table):
        $normal_userdata = $this->_get_normal_userdata($userdata);
        $wpdb->insert($wpdb->users, $normal_userdata);
        $user_id = (int) $wpdb->insert_id;

        // set metadata (the user_metadata table):
        $meta_userdata = $this->_get_meta_userdata($userdata);
        foreach ($meta_userdata as $key => $value) {
            update_user_meta($user_id, $key, $value);
        }

        $user = new WP_User($user_id);

        // set the default role:
        $user->set_role(get_option('default_role'));

        return $user;
    }

    /**
     * Get a RestAuthUser from a given username.
     */
    private function _get_ra_user($username) {
        if (array_key_exists($username, $this->usercache)) {
            return $this->usercache[$username];
        } else {
            $user = new RestAuthUser($this->_get_conn(), $username);
            $this->usercache[$username] = $user;
            return $user;
        }
    }

    /**
     * Update a users properties and roles from RestAuth.
     *
     * @param $user: @WP_User
     *
     * @seealso edit_user() in wp-admin/includes/user.php
     *
     * @todo: Actually handle roles.
     * @todo: wp_update_user actually triggers update_user, which causes
     *        another get()
     */
    private function _update_user($user) {
        global $wpdb;
        error_log("_update_user (" . $_SERVER['REQUEST_METHOD'] . "): " . $user->user_login);

        $userdata = array(
            'user_login' => $user->user_login,
        );

        $userdata = $this->_get_updated_userdata($userdata);

        // update properties of user object:
        foreach ($userdata as $key => $value) {
            $user->$key = $value;
        }

        // insert normal user data (directly in the wp_users table):
        $normal_userdata = $this->_get_normal_userdata($userdata);
        $wpdb->update($wpdb->users, $normal_userdata, array('ID' => $user->ID));

        // set metadata (the user_metadata table):
        $meta_userdata = $this->_get_meta_userdata($userdata);
        foreach ($meta_userdata as $key => $value) {
            update_user_meta($user->ID, $key, $value);
        }
    }

    /**
     * Take an array of user properties, updates it with data from RestAuth.
     *
     * NOTE: This sets all mapped keys, even if not locally present.
     *      This means that all mapped properties are always present after
     *      this method. Good for updates, not as good for inserts.
     */
    private function _get_updated_userdata($userdata) {
        $ra_user = $this->_get_ra_user($userdata['user_login']);
        $ra_props = $ra_user->getProperties();

        foreach ($this->get_global_mappings() as $key => $ra_key) {
            if (!is_string($ra_props[$ra_key])) {
                $userdata[$key] = '';
            } elseif ($ra_props[$ra_key] != $userdata[$key]) {
                $userdata[$key] = $ra_props[$ra_key];
            }
        }

        foreach ($this->get_local_mappings() as $key => $ra_key) {
            $ra_key = 'wordpress ' . $ra_key;

            if (!is_string($ra_props[$ra_key])) {
                $userdata[$key] = '';
            } elseif ($ra_props[$ra_key] != $userdata[$key]) {
                $userdata[$key] = $ra_props[$ra_key];
            }
        }

        return $userdata;
    }

    /**
     * Get normal userdata.
     *
     * This takes an array and returns a subset of the array that represents
     * properites that are "normal" userdata. This data is saved directly in
     * the wp_user table and must be set via $wpdb->insert.
     */
    private function _get_normal_userdata($userdata) {
        $new_data = array();

        foreach ($userdata as $key => $value) {
            if (in_array($key, $this->_normal_properties)) {
                $new_data[$key] = $value;
            }
        }

        return $new_data;
    }

    /**
     * Get meta userdata.
     *
     * Like _get_normal_userdata, but returns exactly the opposite subset.
     * Properties returned by this array must be set with update_user_meta.
     */
    private function _get_meta_userdata($userdata) {
        $new_data = array();

        foreach ($userdata as $key => $value) {
            if (! in_array($key, $this->_normal_properties)) {
                $new_data[$key] = $value;
            }
        }

        return $new_data;
    }

    # Reference: http://codex.wordpress.org/Plugin_API/Action_Reference
    #http://codex.wordpress.org/Plugin_API/Action_Reference/delete_user
    #http://codex.wordpress.org/Plugin_API/Action_Reference/password_reset
    #http://codex.wordpress.org/Plugin_API/Action_Reference/personal_options_update
    #http://codex.wordpress.org/Plugin_API/Action_Reference/profile_update
    #http://codex.wordpress.org/Plugin_API/Action_Reference/register_form
    #http://codex.wordpress.org/Plugin_API/Action_Reference/register_post
    #http://codex.wordpress.org/index.php?title=Plugin_API/Action_Reference/retrieve_password&action=edit&redlink=1
    #http://codex.wordpress.org/index.php?title=Plugin_API/Action_Reference/update_option_(option_name)&action=edit&redlink=1
    #http://codex.wordpress.org/Plugin_API/Action_Reference/user_register
}

$myRestAuthPlugin = new RestAuthPlugin();

/**
 * Send email notifications to admins.
 *
 * This function is a direct copy of the unplugged version that without
 * the last few lines that send a notification to the user (since we do not
 * auto-generate a password, we don't have to send it to the user via an
 * unsecure connection).
 */
function wp_new_user_notification($user_id, $plaintext_pass = '') {
    $user = new WP_User($user_id);

    $user_login = stripslashes($user->user_login);
    $user_email = stripslashes($user->user_email);

    // The blogname option is escaped with esc_html on the way into the database in sanitize_option
    // we want to reverse this for the plain text arena of emails.
    $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

    $message  = sprintf(__('New user registration on your site %s:'), $blogname) . "\r\n\r\n";
    $message .= sprintf(__('Username: %s'), $user_login) . "\r\n\r\n";
    $message .= sprintf(__('E-mail: %s'), $user_email) . "\r\n";

    @wp_mail(get_option('admin_email'), sprintf(__('[%s] New User Registration'), $blogname), $message);
}

?>
