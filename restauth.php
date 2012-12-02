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
    private $global_mappings;
    private $local_mappings;
    private $blacklist;

    private $option_name = 'restauth_options';
    // TODO: reset this to one before release
    var $db_version = 1;

    function __construct() {
        $this->options = get_option($this->option_name);

        if (is_admin()) {
            $options_page = new RestAuthOptionsPage($this, $this->option_name, __FILE__, $this->options);
            add_action('admin_init', array($this, 'check_options'));
        }

        // setting a new password:
        add_action('check_passwords', array($this, 'check_passwords'), 20, 3);

        // authentication
        add_filter('authenticate', array($this, 'authenticate'), 20, 3);

        // load profile_data:
        add_action('personal_options', array($this, 'fetch_user_profile'), 20, 2);
        // load someone elses profile (TODO: really?)::
//        add_action('edit_user_profile', array($this, 'fetch_user_profile'), 20, 2);

        // update own personal options
        add_action('profile_update', array($this, 'update_profile'), 20, 2);

        // update someone elses profile (admins):
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
     * Actually authenticate the user.
     */
    public function authenticate($user, $username, $password) {
        if ($_SERVER['REQUEST_METHOD'] != 'POST') {
            return $user;
        }

        $ra_user = $this->_get_ra_user($username);

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
        if (strlen($pass1) > 0 && strcmp($pass1, $pass2) === 0) {
            $ra_user = $this->_get_ra_user($username);
            $ra_user->setPassword($pass1);
        }
    }

    /**
     * Update local profile before viewing it.
     *
     * Called with profile.php and (most likely) user-edit.php
     *
     * @TODO: Investigate behaviour with user-edit.php
     * @todo: update $user->user_registered information
     */
    public function fetch_user_profile($user) {
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
    private function _global_mappings() {
        if (is_array($this->global_mappings)) {
            return $this->global_mappings;
        }

        $local_mappings = $this->_local_mappings();
        $blacklist = $this->_blacklist();

        $this->global_mappings = array();
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
                $this->global_mappings[$local] = $remote;
            }
        }
        return $this->global_mappings;
    }

    /**
     * A mapping defining how local user properties map to RestAuth props.
     */
    private function _local_mappings() {
        if (is_array($this->local_mappings)) {
            return $this->local_mappings;
        }

        $blacklist = $this->_blacklist();

        $this->local_mappings = array();
        foreach (explode("\n", $this->options['local_mappings']) as $line) {
            $trimmed = trim($line);
            if (strpos($trimmed, '|') === false) {
                $local = $trimmed;
                $remote = $trimmed;
            } else {
                list($local, $remote) = explode('|', $trimmed);
            }
            if (!in_array($local, $blacklist)) {
                $this->local_mappings[$local] = $remote;
            }
        }
        return $this->local_mappings;
    }

    /**
     * A list of properties that should never be synced to RestAuth.
     */
    private function _blacklist() {
        if (is_array($this->blacklist)) {
            return $this->blacklist;
        }

        $this->blacklist = array();
        foreach (explode("\n", $this->options['blacklist']) as $line) {
            $this->blacklist[] = trim($line);
        }

        if (!in_array('user-pass', $this->blacklist)) {
            $this->blacklist[] = 'user_pass';
        }

        return $this->blacklist;
    }

    /**
     * Called when updating a profile.
     *
     * @todo: this hook also receiveds group-information.
     */
    public function update_profile($userid, $old_data) {
        $user = get_userdata($userid);
        $ra_user = $this->_get_ra_user($user->user_login);
        $ra_props = $ra_user->getProperties();

        $ra_set_props = array();
        $ra_rm_props = array();

        $global_mappings = $this->_global_mappings();
        $local_mappings = $this->_local_mappings();

        foreach ($global_mappings as $key => $ra_key) {
            $this->_handle_prop($user, $key, $ra_key, $ra_props,
                $ra_set_props, $ra_rm_props);
        }
        foreach ($local_mappings as $key => $ra_key) {
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
     * @todo get properties from restauth service
     * @todo get roles from restauth service
     */
    private function _create_user($username) {
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
     */
    private function _update_user($user) {
        // $newuser is an object that is populated with properties just like in
        // edit_user(). wp_update_user is called at the bottom of this
        // function.
        $newuser = new stdClass;
        $newuser->ID = $user->ID;
        $newuser->user_login = $user->user_login;

        $ra_user = $this->_get_ra_user($user->user_login);
        $ra_props = $ra_user->getProperties();

        foreach ($this->_global_mappings() as $key => $ra_key) {
            if (!is_string($ra_props[$ra_key])) {
                $newuser->$key = '';
            } elseif ($ra_props[$ra_key] != $user->$key) {
                $newuser->$key = $ra_props[$ra_key];
            }
        }

        foreach ($this->_local_mappings() as $key => $ra_key) {
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
