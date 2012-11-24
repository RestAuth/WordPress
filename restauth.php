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

        # todo: make this configurable via settings pannel
        $this->conn = new RestAuthConnection(
            $this->options['server'], $this->options['user'],
            $this->options['password']);

        if (is_admin()) {
            $options_page = new RestAuthOptionsPage($this, $this->option_name, __FILE__, $this->options);
            add_action('admin_init', array($this, 'check_options'));
        }

        add_filter('authenticate', array($this, 'authenticate'), 20, 3);
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

        if ($current_db_version < 1) {
            foreach ($default_options as $key => $value) {
                // Handle migrating existing options from before we stored a db_version
                if (! isset($this->options[$key])) {
                    $this->options[$key] = $value;
                }
            }
        }
    }

    /**
     * Actually authenticate the user.
     */
    public function authenticate($user, $username, $password) {
        if ($_SERVER['REQUEST_METHOD'] != 'POST') {
            return $user;
        }

        if (array_key_exists($username, $this->usercache)) {
            $user = $this->usercache[$username];
        } else {
            $user = new RestAuthUser($this->conn, $username);
            $this->usercache[$username] = $user;
        }

        if ($user->verifyPassword($password)) {
            $user = get_user_by('login', $username);
            if (!$user) {
                return $this->_create_user($username);
            }
            return $user;
        } else {
            return null;
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

#add_action('publish_post', array('RestAuthPlugin', 'send'));
#
# or with a class - might be good?
# $myEmailClass = new emailer();
# add_action('publish_post', array($myEmailClass, 'send'));
?>
