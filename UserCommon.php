<?php
/**
 * @file AB-STORE / UserCommon.php
 * Created: 09.09.14 / 1:47
 */

namespace User {
    require_once __DIR__ . "/vendor/autoload.php";
    require_once __DIR__ . "/UserCommon.php";
    require_once __DIR__ . "/UserModel.php";
    require_once __DIR__ . "/UserInterface.php";
}


namespace User\Common {

    class Single
    {
        public static function getInstance()
        {
            static $instance = null;
            if (null === $instance) {
                $instance = new static();
            }
            return $instance;
        }

        protected function __construct() { }

        private function __clone() { }

        private function __wakeup() { }

        public static $ADMIN_LEVEL = 255;
        public static $USER_NAME_VERIFICATION_REGEX;
        public $settings = [];
        private $errors = []; ///< todo delete this collection
        //        private $messages = []; ///< todo delete this collection

        //        public function add_message($message) { $this->messages[] = $message; }

        public function add_error($error) { $this->errors[] = $error; }

        //        public function get_messages_collection() { return $this->messages; }

        public function get_errors_collection() { return $this->errors; }
    }

    $memo = Single::getInstance();

    $memo->settings = [
        'ALLOW_REMEMBERME_BY_DEFAULT'      => true,
        'ALLOW_AUTO_SIGNIN_AFTER_VERIFY'   => true,
        'ALLOW_UTF8_USERNAMES'             => true,
        'ALLOW_NO_PASSWORD'                => true,
        "ALLOW_NO_PASSWORD_RETYPE"         => true,
        'ALLOW_NO_CAPTCHA'                 => true,
        'ALLOW_ADMIN_TO_REGISTER_NEW_USER' => true,
        'ALLOW_USER_REGISTRATION'          => true,

        /**
         * Configuration for: Hashing strength
         * This is the place where you define the strength of your password hashing/salting
         *
         * To make password encryption very safe and future-proof, the PHP 5.5 hashing/salting functions
         * come with a clever so called COST FACTOR. This number defines the base-2 logarithm of the rounds of hashing,
         * something like 2^12 if your cost factor is 12. By the way, 2^12 would be 4096 rounds of hashing, doubling the
         * round with each increase of the cost factor and therefore doubling the CPU power it needs.
         * Currently, in 2013, the developers of this functions have chosen a cost factor of 10, which fits most standard
         * server setups. When time goes by and server power becomes much more powerful, it might be useful to increase
         * the cost factor, to make the password hashing one step more secure. Have a look here
         * (@see https://github.com/panique/php-login/wiki/Which-hashing-&-salting-algorithm-should-be-used-%3F)
         * in the BLOWFISH benchmark table to get an idea how this factor behaves. For most people this is irrelevant,
         * but after some years this might be very very useful to keep the encryption of your database up to date.
         *
         * Remember: Every time a user registers or tries to log in (!) this calculation will be done.
         * Don't change this if you don't know what you do.
         *
         * To get more information about the best cost factor please have a look here
         * @see http://stackoverflow.com/q/4443476/1114320
         *
         * This constant will be used in the login and the registration class.
         */
        'HASH_COST_FACTOR'                 => 10,
        /**
         * Configuration for: Cookies
         * Please note: The COOKIE_DOMAIN needs the domain where your app is,
         * in a format like this: .mydomain.com
         * Note the . in front of the domain. No www, no http, no slash here!
         * For local development, use false because .127.0.0.1 or .localhost don't work inside Chrome
         * but when deploying you should change this to your real domain, like '.mydomain.com' !
         * The leading dot makes the cookie available for sub-domains too.
         * @see http://stackoverflow.com/q/9618217/1114320
         * @see http://www.php.net/manual/en/function.setcookie.php
         * @see http://stackoverflow.com/questions/1134290/cookies-on-localhost-with-explicit-domain
         *
         * COOKIE_RUNTIME: How long should a cookie be valid ? 1209600 seconds = 2 weeks
         * COOKIE_DOMAIN: The domain where the cookie is valid for, like '.mydomain.com'
         * COOKIE_SECRET_KEY: Put a random value here to make your app more secure. When changed, all cookies are reset.
         */
        "COOKIE_RUNTIME"                   => 1209600,
        "COOKIE_DOMAIN"                    => "." . $_SERVER['SERVER_NAME'],
        "COOKIE_SECRET_KEY"                => "_#32PS{+$7____;%;%;___8sfSDFrtre-*766pMJFe-92s",

        "MAIL_VERIFY_FN"                   => function () { },
        "MAIL_RESET_PASSWORD_FN"           => function () { },
    ];

    /**
     * @deprecated
     * @var
     */
    $memo::$USER_NAME_VERIFICATION_REGEX = '/^[0-9 \-_' . ($memo->settings['ALLOW_UTF8_USERNAMES'] ? '[:alpha:]' : 'a-z') . ']{2,64}$/iu';

    function get_exit_result()
    {
        $memo = Single::getInstance();
        return count($memo->get_errors_collection())
            ? ['error' => 'Signin fault', 'errors' => $memo->get_errors_collection()]
            : ['response' => []];
    }

    /*
     *
     * check the possible LOGIN actions:
     * 1.  login via session data (happens each time user opens a page on your php project
     *     AFTER he has successfully logged in via the login form)
     * 2.  login via cookie
     */
    function reveal_user_cookie_session()
    {
        // login with cookie
        if (isset($_COOKIE['rememberme'])) {
            auto_start_cookie_session();
        }
        else {
            return false;
        }
        return true;
    }

    function get_session_cookie_part($partName)
    {
        list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
        return $$partName;
    }

    /**
     * Logs in via the Cookie
     * @return bool success state of cookie login
     */
    function auto_start_cookie_session()
    {
        $memo = Single::getInstance();
        if (!isset($_COOKIE['rememberme'])) return false;
        // extract data from the cookie
        list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
        // check cookie hash validity
        if (
            $hash == hash('sha256', $user_id . ':' . $token . $memo->settings['COOKIE_SECRET_KEY'])
            && !empty($token)
            // cookie looks good, try to select corresponding user
            // get real token from database (and all other data)
            && \User\Common\Model\is_user_session_valid($user_id, $token)
        ) {
            // Cookie token usable only once. Hrm ???
            set_cookie_session($user_id, $token);
            return true;
        }
        else {
            // A cookie has been used but is not valid... we delete it
            delete_cookie_session();
            $memo->add_error('%MESSAGE_COOKIE_INVALID%');

            return false;
        }
    }

    /**
     * Create all data needed for remember me cookie connection on client and server side
     *
     * @param        $user_id
     * @param string $current_rememberme_token
     */
    function set_cookie_session($user_id, $current_rememberme_token = '')
    {
        $memo = Single::getInstance();
        //
        // Generate cookie string that consists of userid, random string and combined hash of both
        $random_token_string = hash('sha256', mt_rand()); // Generate 64 char random string and
        $cookie_string_hash  = hash('sha256', $user_id . ':' . $random_token_string . $memo->settings['COOKIE_SECRET_KEY']);
        $cookie_string       = $user_id . ':' . $random_token_string . ':' . $cookie_string_hash;
        //
        // Update session ('rememberme') token hash. Store $random_token_string in current user data
        \User\Common\Model\update_session_token($user_id, $random_token_string, $current_rememberme_token);
        //
        // Set cookie $_COOKIE['rememberme']
        setcookie('rememberme', $cookie_string, time() + $memo->settings['COOKIE_RUNTIME'], "/", $memo->settings['COOKIE_DOMAIN']);
    }

    /**
     * Delete all data needed for remember me cookie connection on client and server side
     */
    function delete_cookie_session()
    {
        $memo = Single::getInstance();
        // if database connection opened and remember me cookie exist
        if (isset($_COOKIE['rememberme'])) {
            //
            // extract data from the cookie
            list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
            // check cookie hash validity
            if ($hash == hash('sha256', $user_id . ':' . $token . $memo->settings['COOKIE_SECRET_KEY']) && !empty($token)) {
                \User\Common\Model\close_session($token, $user_id);
            }
        }
        // set the rememberme-cookie to ten years ago (3600sec * 365 days * 10).
        // that's obviously the best practice to kill a cookie via php
        // @see http://stackoverflow.com/a/686166/1114320
        setcookie('rememberme', false, time() - (3600 * 3650), '/', $memo->settings['COOKIE_DOMAIN']);
    }

    function is_allow_signup()
    {
        $user_id = get_session_cookie_part('user_id');
        $memo = Single::getInstance();
        $user = \User\Common\Model\get_user_by_id($user_id);
        return (
            !is_user_signed_in($user_id) && $memo->settings['ALLOW_USER_REGISTRATION']
            || $memo->settings['ALLOW_ADMIN_TO_REGISTER_NEW_USER'] && $user['user_access_level'] == $this->ADMIN_LEVEL
        );
    }

    /**
     * @todo rewrite for using model instead of PHP SESSION
     * Simply return the current state of the user's login
     *
     * @param $user_id
     *
     * @return bool user's login status
     */
    function is_user_signed_in($user_id)
    {
        return \User\Common\Model\is_session_exist($user_id);
    }

    /**
     * Crypt the $password with the PHP 5.5's password_hash()
     *
     * @param $password string
     *
     * @return bool|false|string - 60 character hash password string
     */
    function get_hash_of_password($password)
    {
        $memo = Single::getInstance();
        // check if we have a constant HASH_COST_FACTOR defined (in config/config.php),
        // if so: put the value into $hash_cost_factor, if not, make $hash_cost_factor = null
        $hash_cost_factor = $memo->settings['HASH_COST_FACTOR'];
        // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 character hash string
        // the PASSWORD_DEFAULT constant is defined by the PHP 5.5, or if you are using PHP 5.3/5.4, by the password hashing
        // compatibility library. the third parameter looks a little bit shitty, but that's how those PHP 5.5 functions
        // want the parameter: as an array with, currently only used with 'cost' => XX.
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $hash_cost_factor]);
    }

}


namespace User\Common\Signin {
    use User\Common\Single;

    function check_post($user_email, $user_password)
    {
        $memo = Single::getInstance();
        while (true) {
            $user_email = trim($user_email);
            if (empty($user_password)) {
                $memo->add_error('%MESSAGE_PASSWORD_EMPTY%');
                // if POST data (from login form) contains non-empty user_email and non-empty user_password
                break;
            }
            if (empty($user_email) || !filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
                $memo->add_error('%MESSAGE_EMAIL_INVALID%');
                break;
            }
            //
            // database query, getting all the info of the selected user
            $user_object = \User\Common\Model\get_user_by_id($user_email, 'email');
            //
            // if this user not exists
            if (!isset($user_object['id'])) {
                // was '%MESSAGE_USER_DOES_NOT_EXIST%' before, but has changed to '%MESSAGE_LOGIN_FAILED%'
                // to prevent potential attackers showing if the user exists
                $memo->add_error('%MESSAGE_LOGIN_FAILED%');
                break;
            }
            if ($user_object['user_active'] != 1) {
                $memo->add_error('%MESSAGE_ACCOUNT_NOT_ACTIVATED%');
                break;
            }
            if (($user_object['user_failed_logins'] >= 3) && ($user_object['user_last_failed_login'] > (time() - 30))) {
                $memo->add_error('%MESSAGE_PASSWORD_WRONG_3_TIMES%');
                // using PHP 5.5's password_verify() function to check if the provided passwords fits to the hash of that user's password
                break;
            }
            // PHP Core: password_verify - Checks if the given hash matches the given options.
            if (!password_verify($user_password, $user_object['user_password_hash'])) {
                // increment the failed login counter for that user
                \User\Common\Model\increment_signin_fails($user_email);
                $memo->add_error('%MESSAGE_PASSWORD_WRONG%');
                // has the user activated their account with the verification email
                break;
            }
            return true;
        }
        return false;
    }

    function ok($user_email, $user_rememberme, $user_password = null)
    {
        $memo        = Single::getInstance();
        $user_object = \User\Common\Model\get_user_by_id($user_email, 'email');
        $user_id     = $user_object['id'];
        //
        // reset the failed login counter for that user
        \User\Common\Model\reset_signin_fails($user_object['email']);
        //
        // if user has check the "remember me" checkbox, then generate token and write cookie
        if (isset($user_rememberme)) \User\Common\set_cookie_session($user_id);
        //
        // OPTIONAL: recalculate the user's password hash
        // DELETE this if-block if you like, it only exists to recalculate users's hashes when you provide a cost factor,
        // by default the script will use a cost factor of 10 and never change it.
        // check if the have defined a cost factor in config/hashing.php
        try {
            if ($memo->settings['HASH_COST_FACTOR'] && !empty($user_password)) {
                // check if the hash needs to be rehashed
                if (password_needs_rehash($user_object['user_password_hash'], PASSWORD_DEFAULT, ['cost' => $memo->settings['HASH_COST_FACTOR']])) {
                    $rehashingStatus = \User\Common\Model\set_password($user_id, $user_password);
                    if ($rehashingStatus) {
                        // @todo writing new hash was successful. you should now output this to the user ;)
                    }
                    else {
                        // @todo writing new hash was NOT successful. you should now output this to the user ;)
                    }
                }
            }
        } catch (\Exception $e) {
        }
        return true;
    }
}

namespace User\Common\Signup {
    /*
     * 2.
     * sends an email to the provided email address
     * @return boolean gives back true if mail has been sent, gives back false if no mail could been sent
     */
    use User\Common\Single;

    function send_mail_verify($user_email, $user_activation_hash, $mailVerifySignup)
    {
        $memo     = Single::getInstance();
        $password = $_SESSION['tmp_user_password_new'];
        unset($_SESSION['tmp_user_password_new']);
        try {
            $isMailSuccess = $mailVerifySignup([
                'password' => $password,
                'code'     => $user_activation_hash,
                'email'    => $user_email
            ]);
        } catch (\Exception $e) {
            \Invntrm\bugReport2('signup,verify', $e);
            $isMailSuccess = false;
        }
        if (!$isMailSuccess) {
            $memo->add_error('%MESSAGE_VERIFICATION_MAIL_NOT_SENT%');
            return false;
        }
        else {
            return true;
        }
    }

    function add_user($user_name, $user_email, $user_password_new = null)
    {
        $memo = Single::getInstance();
        if ($user_id = \User\Common\Model\is_user_exist($user_email))
            return $user_id;
        if ($memo->settings['ALLOW_NO_PASSWORD'] && !$user_password_new) {
            $user_password_new = \Invntrm\generateStrongPassword();
        }
        $user_password_hash                = \User\Common\get_hash_of_password($user_password_new); // crypt the user's password with the PHP 5.5's password_hash() function.
        $user_id                           = \User\Common\Model\set_data($user_name, $user_email, $user_password_hash);
        $_SESSION['tmp_user_password_new'] = $user_password_new;
        return !empty($user_id) ? $user_id : false;
    }

}

namespace User\Common\Reset {
    use User\Common\Single;

    /**
     * @deprecated
     * @todo bring validate
     *
     * @param $user_email
     *
     * @return bool
     */
    function check_post($user_email)
    {
        $memo       = Single::getInstance();
        $user_email = trim($user_email);
        //
        if (empty($user_email)) {
            $memo->add_error('%MESSAGE_USERNAME_EMPTY%');
        }
        else {
            // generate timestamp (to see when exactly the user (or an attacker) requested the password reset mail)
            // btw this is an integer ;)
            $temporary_timestamp = time();
            // generate random hash for email password reset verification (40 char string)
            $verification_code = sha1(uniqid(mt_rand(), true));
            //
            // if this user exists
            if (\User\Common\Model\is_user_exist($user_email)) {
                //
                // store his password_reset_hash in the DB
                $isHashStored = \User\Common\Model\set_reset_password_request(
                    $verification_code,
                    $temporary_timestamp,
                    $user_email
                );
                //
                // check if exactly one row was successfully changed:
                if ($isHashStored) {
                    return $verification_code;
                }
                else {
                    $memo->add_error('%MESSAGE_DATABASE_ERROR%');
                }
            }
            else {
                $memo->add_error('%MESSAGE_USER_DOES_NOT_EXIST%');
            }
        }
        // return false (this method only returns true when the database entry has been set successfully)
        return false;
    }


    /**
     * @deprecated
     * @todo довести
     * 2.
     * Sends the password-reset-email.
     *
     * @param $user_email
     * @param $verification_code
     *
     * @param $mailResetPassword
     *
     * @return bool
     */
    function send_mail_verify($user_email, $verification_code, $mailResetPassword)
    {
        $memo = Single::getInstance();
        try {
            $isMailSuccess = $mailResetPassword([
                'code'  => $verification_code,
                'email' => $user_email
            ]);
        } catch (\Exception $e) {
            \Invntrm\bugReport2('signup fail', $e);
            $isMailSuccess = false;
        }
        if (!$isMailSuccess) {
            $memo->add_error('%MESSAGE_VERIFICATION_MAIL_NOT_SENT%');
            return false;
        }
        else {
            return true;
        }
    }

    /**
     * @deprecated
     * @todo довести
     * 4.
     * Checks and writes the new password.
     *
     * @param $user_email
     * @param $user_password_reset_verify_code
     * @param $user_password_new
     * @param $user_password_repeat
     */
    function set_password($user_email, $user_password_reset_verify_code, $user_password_new, $user_password_repeat)
    {
        $memo = Single::getInstance();
        // TODO: timestamp! Hrm... ??
        $user_email = trim($user_email);
        //
        if (empty($user_email) || empty($user_password_reset_verify_code) || empty($user_password_new) || !$memo->settings['ALLOW_NO_PASSWORD_RETYPE'] && empty($user_password_repeat)) {
            $memo->add_error('%MESSAGE_PASSWORD_EMPTY%');
            // is the repeat password identical to password
        }
        else if (!$memo->settings['ALLOW_NO_PASSWORD_RETYPE'] && $user_password_new !== $user_password_repeat) {
            $memo->add_error('%MESSAGE_PASSWORD_BAD_CONFIRM%');
            // password need to have a minimum length of 6 characters
        }
        else if (strlen($user_password_new) < 6) {
            $memo->add_error('%MESSAGE_PASSWORD_TOO_SHORT%');
            // if database connection opened
        }
        else {
            // crypt the user's password with the PHP 5.5's password_hash() function.
            $user_password_hash = \User\Common\get_hash_of_password($user_password_new);
            $is_update_success  = \User\Common\Model\reset_password($user_password_hash, $user_password_reset_verify_code, $user_email);
            //
            // check if exactly one row was successfully changed:
            if ($is_update_success) {
                // Password changed successfully
                //                $memo->add_message('%MESSAGE_PASSWORD_CHANGED_SUCCESSFULLY%');
            }
            else {
                $memo->add_error('%MESSAGE_PASSWORD_CHANGE_FAILED%');
            }
        }
    }


}