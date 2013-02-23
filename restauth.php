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

    private $option_name = 'restauth_options';
    var $db_version = 1;

    function __construct() {
        $this->options = get_option($this->option_name);

        if (is_admin()) {
            $options_page = new RestAuthOptionsPage($this, $this->option_name, __FILE__, $this->options);
            add_action('admin_init', array($this, 'check_options'));
        }

        // pre-user registration:
        add_action('register_post', array($this, 'pre_register'), 20, 3);

        // user registration:
        add_action('user_register', array($this, 'register'));

        // attempt to modify registration form:
        if(isset($_GET['action']) && $_GET['action'] == 'register'){
            add_action('register_form', array(&$this, 'register_form'));
            add_filter( 'gettext', array(&$this, 'remove_email_notification_msg'));
        }

        // authentication
        add_filter('authenticate', array($this, 'authenticate'), 20, 3);

        // setting a new password:
        add_action('check_passwords', array($this, 'check_passwords'), 20, 3);

        // load profile_data:
        // Called when viewing your own or someone elses profile
        add_action('personal_options', array($this, 'fetch_user_profile'), 20, 2);
        // load someone elses profile (TODO: really?):
//        add_action('edit_user_profile', array($this, 'fetch_user_profile'), 20, 2);

        // update own personal options
        add_action('profile_update', array($this, 'update_profile'), 20, 2);

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

    public function check_options() {
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
     * Verify that a user does not exist so far.
     *
     * Called by the register_post hook.
     *
     * Called:
     * - POST wp-login.php?action=register - Register a new user
     */
    public function pre_register($user_login, $user_email, $errors) {
        error_log('pre_register');
        if ( $_POST['password'] !== $_POST['repeat_password'] ) {
            $errors->add('passwords_not_matched', "<strong>ERROR</strong>: Passwords must match");
        }
        if ( strlen( $_POST['password'] ) < 8 ) {
            $errors->add('password_too_short', "<strong>ERROR</strong>: Passwords must be at least eight characters long");
        }

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

    /**
     * Register a new user.
     *
     * This function creates a user in RestAuth and sets any properties.
     *
     * If allow_wp_auth is set, updates the locally stored hash (since the
     * current hash is for the auto-generated one), otherwise we set the
     * user_pass field to an empty value.
     *
     * Called by the user_register hook.
     *
     * Called:
     * - POST wp-login.php?action=register - Register a new user
     *
     * @see: wp_insert_user in wp-includes/user.php.
     */
    public function register($userid) {
        global $wpdb;

        error_log("register user with id '$userid'");
        $user = get_user_by('id', $userid);
        $conn = $this->_get_conn();

        $password = $_POST['password'];

        $properties = array();
        foreach ($this->get_global_mappings() as $key => $ra_key) {
            if (isset($user->$key)) {
                $properties[$ra_key] = $user->$key;
            }
        }
        foreach ($this->get_local_mappings() as $key => $ra_key) {
            if (isset($user->$key)) {
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
        if ($_SERVER['REQUEST_METHOD'] != 'POST') {
            return $user;
        }

        $ra_user = $this->_get_ra_user($username);

        error_log("authenticating: '$username', '$password'");
        if ($ra_user->verifyPassword($password)) {
            $user = get_user_by('login', $username);
            if ($user) {
                return $user;
            } elseif (!$user && $this->options['auto_create_user']) {
                return $this->_create_user($username);
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
     * Called:
     * - GET wp-admin/profile.php - View your own profile
     * - GET wp-admin/user-edit.php - View "Edit User" (view other users profile)
     *
     * @todo: update $user->user_registered information
     */
    public function fetch_user_profile($user) {
        error_log("fetch_user_profile");
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
    public function update_profile($userid, $old_data) {
        error_log('update_profile');
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
     * Create a new user
     *
     * @todo get roles from restauth service
     */
    private function _create_user($username) {
        error_log("_create_user '$username'");

        $user_id = wp_create_user($username, $password);#, $username . ($email_domain ? '@' . $email_domain : ''));
        $user = get_user_by('id', $user_id);
        $this->_update_user($user);

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
     * @seealso edit_user() in wp-admin/includes/user.php
     *
     * @todo: Actually handle roles.
     * @todo: wp_update_user actually triggers update_user, which causes
     *        another get()
     */
    private function _update_user($user) {
        // $newuser is an object that is populated with properties just like in
        // edit_user(). wp_update_user is called at the bottom of this
        // function.
        error_log("_update_user: " . $user->user_login);
        $newuser = new stdClass;
        $newuser->ID = $user->ID;
        $newuser->user_login = $user->user_login;

        $ra_user = $this->_get_ra_user($user->user_login);
        $ra_props = $ra_user->getProperties();

        foreach ($this->get_global_mappings() as $key => $ra_key) {
            if (!is_string($ra_props[$ra_key])) {
                $newuser->$key = '';
            } elseif ($ra_props[$ra_key] != $user->$key) {
                $newuser->$key = $ra_props[$ra_key];
            }
        }

        foreach ($this->get_local_mappings() as $key => $ra_key) {
            $ra_key = 'wordpress ' . $ra_key;

            if (!is_string($ra_props[$ra_key])) {
                $newuser->$key = '';
            } elseif ($ra_props[$ra_key] != $user->$key) {
                $newuser->$key = $ra_props[$ra_key];
            }
        }

        // finally call wp_update_user
        wp_update_user(get_object_vars($newuser));
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

?>
