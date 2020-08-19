<?php
/**
 * Plugin Name: Smart E-mail Login
 * Version: 1.0.0
 * Author: diego2k
 * Author URI: https://profiles.wordpress.org/diego2k/
 * Description: Remove username and use only email to login, register and retrieve password in WordPress.
 */

/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

// Make sure we don't expose any info if called directly
if ( !function_exists( 'add_action' ) ) {
	echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
	exit;
}


class SmartEmailLogin {

    /**
     * Main Constructor
     */
    public function __construct() {

        //remove wordpress authentication
        remove_filter('authenticate', 'wp_authenticate_username_password', 20);

        //custom authentication function
        add_filter('authenticate', array($this, 'callback_Authenticate'), 20, 3);

        //Process Gettext for custom strings
        add_action('login_form_login', array($this,'callback_LoginFormLogin'));

        //Assign email to username
        add_action('login_form_register', array($this, 'callback_LoginFormRegister'));

        //Remove error for username, show error for email only.
        add_filter('registration_errors', array($this, 'callback_RegistrationErrors'), 10, 3);

        add_action('login_head', array($this, 'callback_LoginHead'));
        add_action('login_footer', array($this, 'callback_LoginFooter'));

        //Process Retrieve Password
        add_action('login_form_lostpassword', array($this, 'callback_LoginFormLostPassword'));
        add_action('login_form_retrievepassword', array($this, 'callback_LoginFormLostPassword'));

    }

    ############################################################################
    #  Login With Email
    ############################################################################

    /**
     * Custom Authentication function
     */
    public function callback_Authenticate($user, $email, $password) {

        //create new error object and add errors to it.
        $error = new WP_Error();

        if($_SERVER['REQUEST_METHOD'] !== 'POST' ) return $error;

        //Check for empty fields
        if( empty($email) || empty($password) ) {

            if(empty($email)) {
                $error->add('empty_username', __( '<strong>Error</strong>: The email field is empty.' ) );
            }
            else if(!is_email($email)) {
                $error->add('invalid_username', __( '<strong>Error</strong>: Invalid email address.' ) );
            }
            else if(empty($password)) {
                $error->add('empty_password', __( '<strong>Error</strong>: The password field is empty.' ) );
            }

        } else {

            //Check if user exists in WordPress database
            $user = get_user_by('email', $email);

            //bad email
            if( !$user || !wp_check_password($password, $user->user_pass, $user->ID) ) {
                $error->add('incorrect_password', __('<strong>Error</strong>: The email or password you entered do not match.') );
            }
        }

        return $error->has_errors() ? $error : $user;
    }

    public function callback_LoginFormLogin(){
        //Remove "Username" from text
        add_filter('gettext', array($this, 'callback_LoginFormGettext'), 20, 3);
    }

    public function callback_LoginFormGettext($translated_text, $text, $domain ) {

        return $text == 'Username or Email Address' ? __('Email') : $translated_text;
    }

    ############################################################################
    #  Register With Email
    ############################################################################

    /**
     * Hook to registration system,
     * Now the tweak goes here.
     * Username: As WP registration requires username, we need to provide a username while
     * registering. So we assign local part of email as username, ex: demo#demo@example.com
     * and username would be demodemo (no special chars).
     *
     * Duplicate Username: In case username already exists, system tries to change
     * username by adding a random number as suffix. Random number is between
     * 1 to 999. Ex: demodemo_567
     */
    public function callback_LoginFormRegister() {

        if(isset($_POST['user_login']) && isset($_POST['user_email']) && !empty($_POST['user_email'])) {

            //In case user email contains single quote ', WP will add a slash automatically. Yes, emails can use special chars, see RFC 5322
            $_POST['user_email'] = stripslashes($_POST['user_email']);

            // Split out the local and domain parts
            list( $local, ) = explode( '@', $_POST['user_email'], 2 );

            //Sanitize special characters in email fields, if any. Yes, emails can use special chars, see RFC 5322
            $_POST['user_login'] = sanitize_user($local, true);

            $pre_change = $_POST['user_login'];
            //In case username already exists, change it
            while(username_exists($_POST['user_login'])){
                $_POST['user_login'] = $pre_change . '_' . rand(1, 999);
            }
        }

    }

    /**
     * Remove registration message for username
     */
    public function callback_RegistrationErrors($wp_error, $sanitized_user_login, $user_email) {

        if(isset($wp_error->errors['empty_username'])) {
            unset($wp_error->errors['empty_username']);
        }

        if(isset($wp_error->errors['username_exists'])) {
            unset($wp_error->errors['username_exists']);
        }

        return $wp_error;
    }

    /**
     * hide username field
     */
    public function callback_LoginHead() {
        ?>
        <style>#registerform > p:first-child { visibility: hidden; display:none; }</style>
        <?php
    }

    /**
     * Just a backup to remove username field, although css is suffice
     */
    public function callback_LoginFooter() {
        ?>
        <script type="text/javascript">
            try{document.getElementById('registerform').children[0].style.display = 'none';;}catch(e){}
            try{document.getElementById('user_email').focus();}catch(e){}
        </script>
        <?php
    }

    ############################################################################
    #  Reset Password With Email
    ############################################################################

    public function callback_LoginFormLostPassword() {

        global $errors;

        if('POST' == $_SERVER['REQUEST_METHOD'] && isset($_POST['user_login'])) {

            //To skip default wordpress processing.
            $_SERVER['REQUEST_METHOD'] = ':(';

            if(empty($_POST['user_login'])) {
                $errors->errors['empty_username'] = __('You must provide your email.');

                //In case of error, later restore previous REQUEST_METHOD value
                add_action('lost_password', array($this, 'callback_LostPassword'));

            } else if( !is_email($_POST['user_login']) ) {
                $errors->errors['invalid_combo'] = __('Email is invalid.');

                //In case of error, later restore previous REQUEST_METHOD value
                add_action('lost_password', array($this, 'callback_LostPassword'));

            } else { //Don't skip now
                $_SERVER['REQUEST_METHOD'] = 'POST';
            }
        }

        //Change "Retrieve Password" related text
        add_filter('gettext', array($this, 'callback_LostPasswordGettext'), 20, 3);
    }

    public function callback_LostPassword() {
        //Restore right value
        $_SERVER['REQUEST_METHOD'] = 'POST';
    }

    public function callback_LostPasswordGettext($translated_text, $text, $domain ) {

        return $text == 'Username or Email Address' ? __('Email') : $translated_text;
    }
}

New SmartEmailLogin();
