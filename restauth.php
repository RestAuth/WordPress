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

class RestAuthPlugin {
    private $conn;
    private $usercache = array();

    function __construct() {
        # todo: make this configurable via settings pannel
        $this->conn = new RestAuthConnection(
            'http://[::1]:8000', 'example.com', 'nopass');

        #add_action('wp_authenticate', array($this, 'authenticate'), 10, 2);
        add_filter('authenticate', array($this, 'authenticate'), 20, 3);
    }

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
