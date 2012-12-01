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

    private $option_name = 'restauth_options';
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
//        add_action('edit_user_profile', array($this, 'fetch_user_profile'), 20, 2);

        // update own personal options
        add_action('personal_options_update',
            array($this, 'update_user_profile'), 20, 3);
        // update someone elses profile (admins):
        add_action('edit_user_profile_update',
            array($this, 'update_user_profile'), 20, 3);
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
            } else {
                return null;
            }
        } else {
            return null;
        }
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

    public function fetch_user_profile($user) {
        $ra_user = $this->_get_ra_user($user->user_login);

        // fetch properties
        $ra_props = $ra_user->getProperties();

        // Set properties available locally but not remotely
        $ra_set_props = array();
        if (array_key_exists('email', $ra_props)) {
            $user->user_email = $ra_props['email'];
        } elseif(isset($user->user_email) && strlen($user->user_email) > 0) {
            $ra_set_props['email'] = $user->user_email;
        }
        if (array_key_exists('first name', $ra_props)) {
            $user->first_name = $ra_props['first name'];
        } elseif (isset($user->first_name) && strlen($user->first_name) > 0) {
            $ra_set_props['first name'] = $user->first_name;
        }
        if (array_key_exists('last name', $ra_props)) {
            $user->last_name = $ra_props['last name'];
        } elseif (isset($user->last_name) && strlen($user->last_name) > 0) {
            $ra_set_props['last name'] = $user->last_name;
        }
        if (array_key_exists('url', $ra_props)) {
            $user->user_url = $ra_props['url'];
        } elseif (isset($user->user_url) && strlen($user->user_url) > 0) {
            $ra_set_props['url'] = $user->user_url;
        }

        // finally, set properties that weren't set in RestAuth:
        if (count($ra_set_props) > 0) {
            $ra_user->setProperties($ra_set_props);
        }

        // 2. Set all properties as in the RestAuth server
        //die('email: ' . $user->user_email);
    }

    /**
     * Called when pressing the "update profile" button on the profile page.
     */
    public function update_user_profile($userid) {
        die('calling hook');
        $user = get_userdata($userid);
        $ra_user = $this->_get_ra_user($user->user_login);

        die($_POST['email']);

        if (strlen($_POST['email']) > 0 && strcmp($user->email, $_POST['email']) != 0) {
            $ra_user->setProperty('email', $_POST['email']);
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
