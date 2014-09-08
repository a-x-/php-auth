<?php
require_once 'User.php';
require_once __DIR__ . '/../../../vendor/a-x-/backend/Mq.php';

/**
 * handles the user login/logout/session
 * @author  devplanete (2013 - 2014)
 * @author  Panique (2012 - 2013)
 * @link    https://github.com/devplanete/php-login-advanced
 * @license http://opensource.org/licenses/MIT MIT License
 */
class PHPLogin
{
    public $ADMIN_LEVEL = 255;
    /**
     * @var boolean $password_reset_link_is_valid Marker for view handling
     */
    public $password_reset_link_is_valid = false;
    /**
     * @var boolean $password_reset_was_successful Marker for view handling
     */
    public $password_reset_was_successful = false;
    /**
     * @var array $errors Collection of error messages
     */
    public $errors = [];
    /**
     * @var array $messages Collection of success / neutral messages
     */
    public $messages = [];

    public $USER_NAME_VERIFICATION_REGEX = '';

    public $REQUEST_PATH = '';

    public $REQUEST_PATH_API = '';

    public $REQUEST_METHOD = '';

    private $settings = [];

    public function setting($key){return \Invntrm\true_get($this->settings, $key);}

    /**
     * the function "__construct()" automatically starts whenever an object of this class is created,
     * you know, when you do "$login = new PHPLogin();"
     */
    public function __construct($configPath = '', $settings = [])
    {
        // check for minimum PHP version
        if (version_compare(PHP_VERSION, '5.3.7', '<')) {
            exit('Sorry, this script does not run on a PHP version smaller than 5.3.7 !');
        }
        else if (version_compare(PHP_VERSION, '5.5.0', '<')) {
            // if you are using PHP 5.3 or PHP 5.4 you have to include the password_api_compatibility_library.php
            // (this library adds the PHP 5.5 password hashing functions to older versions of PHP)
            require_once(__DIR__ . '/libraries/password_compatibility_library.php');
        }
        //
        // include the config
        // @deprecated
        require_once($configPath ? $configPath : __DIR__ . '/sample/config/config.php');
        //
        // Define settings
        $this->settings = array_merge([
            'BASE_API_ENDPOINT'                => '/api/profile/',
            'BASE_VIEW_ENDPOINT'               => '/profile/',
            'MAIL_TEMPLATES_DIR'               => '/_components/auth_mail_template',
            'ALLOW_REMEMBERME_BY_DEFAULT'      => true,
            'ALLOW_AUTO_SIGNIN_AFTER_VERIFY'   => true,
            'ALLOW_UTF8_USERNAMES'             => true,
            'ALLOW_NO_PASSWORD'                => true,
            "ALLOW_NO_PASSWORD_RETYPE"         => true,
            'ALLOW_NO_CAPTCHA'                 => true,
            "EMAIL_BODY_TYPE"                  => 'html',
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
            'EMAIL'                            => [
                'NAME'                 => 'Проект',
                'ADDRESS'              => '',
                'VERIFICATION_SUBJECT' => 'Подтверждение',
                'RESET_SUBJECT'        => 'Сброс парполя',

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
            ],
            "COOKIE_RUNTIME"                   => 1209600,
            "COOKIE_DOMAIN"                    => "." . $_SERVER['SERVER_NAME'],
            "COOKIE_SECRET_KEY"                => "___1gp@#32PS{+$78sfSDFrtre-*766pMJFe-92s"
        ], $settings);
        //
        // Password-retype do not be true when allow-no-password is true
        if (!empty($this->settings['ALLOW_NO_PASSWORD']) && !empty($this->settings['ALLOW_NO_PASSWORD_RETYPE'])) {
            $this->settings['ALLOW_NO_PASSWORD_RETYPE'] =
                $this->settings['ALLOW_NO_PASSWORD_RETYPE'] || $this->settings['ALLOW_NO_PASSWORD'];
        }
        //
        // Add absolute endpoints values
        $this->settings['BASE_API_ENDPOINT_ABSOLUTE'] = 'http://' . $_SERVER['HTTP_HOST'] . $this->settings['BASE_API_ENDPOINT'];
        $this->settings['BASE_VIEW_ENDPOINT_ABSOLUTE'] = 'http://' . $_SERVER['HTTP_HOST'] . $this->settings['BASE_VIEW_ENDPOINT'];

        //
        $this->USER_NAME_VERIFICATION_REGEX = '/^[0-9 \-_' . ($this->settings['ALLOW_UTF8_USERNAMES'] ? '[:alpha:]' : 'a-z') . ']{2,64}$/iu';
        $this->REQUEST_PATH                 = (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        $this->REQUEST_PATH_API             = @$_REQUEST['api_path'];
        $this->REQUEST_METHOD               = strtolower($_SERVER['REQUEST_METHOD']);
        $GLOBALS['login']                   = $this;
        //
        // create/read session
        \Invntrm\true_session_start();
        //
        // Execute login/registration action
        // this function looks into $_POST and $_GET to execute the corresponding login/registration action.
        if ($this->revealUserSession())
            $this->runSigninActions();
        else
            $this->runNoSignActions();
    }

    /*
     *
     * check the possible LOGIN actions:
     * 1.  login via session data (happens each time user opens a page on your php project
     *     AFTER he has successfully logged in via the login form)
     * 2.  login via cookie
     */
    public function revealUserSession()
    {
        //
        // 1.
        // Login with session
        if (!empty($_SESSION['user_logged_in'])) {
        }
        //
        // 2.
        // login with cookie
        elseif (isset($_COOKIE['rememberme'])) {
            $this->loginWithCookieData();
        }
        else {
            return false;
        }
        return true;
    }

    /**
     * Logs in via the Cookie
     * @return bool success state of cookie login
     */
    private function loginWithCookieData()
    {
        if (isset($_COOKIE['rememberme'])) {
            // extract data from the cookie
            list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
            // check cookie hash validity
            if ($hash == hash('sha256', $user_id . ':' . $token . $this->settings['COOKIE_SECRET_KEY']) && !empty($token)) {
                // cookie looks good, try to select corresponding user
                // get real token from database (and all other data)
                $userData = (new \AlxMq())->req(
                    'user[id=* && user_connections.user_rememberme_token]?id, user_name, email, user_access_level',
                    'is', [(int)$user_id, (string)$token]
                );

                if (isset($userData)) {
                    $this->writeUserDataIntoSession($userData); // write user data into PHP SESSION [a file on your server]

                    // Cookie token usable only once
                    $this->newRememberMeCookie($token);
                    return true;
                }
            }
            // A cookie has been used but is not valid... we delete it
            $this->deleteRememberMeCookie();
            $this->errors[] = '%MESSAGE_COOKIE_INVALID%';
        }
        return false;
    }

    /**
     * write user data into PHP SESSION [a file on your server]
     */
    public function writeUserDataIntoSession($user_object)
    {
        $user_object                   = (array)$user_object;
        $_SESSION['user_id']           = $user_object['id'];
        $_SESSION['user_name']         = $user_object['user_name'];
        $_SESSION['user_email']        = $user_object['email'];
        $_SESSION['user_access_level'] = $user_object['user_access_level'];
        $_SESSION['user_logged_in']    = 1;
    }

    /**
     * Create all data needed for remember me cookie connection on client and server side
     */
    public function newRememberMeCookie($current_rememberme_token = '')
    {
        // generate 64 char random string and store it in current user data
        $random_token_string = hash('sha256', mt_rand());
        $paramsString        = 'user_rememberme_token=*, user_login_agent=*, user_login_ip=*, user_login_datetime=*, user_last_visit=*';
        $sigma               = 'sssss';
        $values              = [$random_token_string, $_SERVER['HTTP_USER_AGENT'], $_SERVER['REMOTE_ADDR']];
        //
        // record the new token for this user/device
        if ($current_rememberme_token == '') {
            (new \AlxMq())->req(
                "user_connections[user_id=*,{$paramsString}]>",
                "i{$sigma}",
                array_merge((int)[$_SESSION['user_id']], $values)
            );
        }
        //
        // update current rememberme token hash by a new one
        else {
            (new \AlxMq())->req(
                "user_connections[user_id=* && user_rememberme_token=*]?,{$paramsString}",
                "is{$sigma}",
                array_merge([(int)$_SESSION['user_id'], $current_rememberme_token], $values)
            );
        }
        //
        // generate cookie string that consists of userid, random string and combined hash of both
        $cookie_string_first_part = $_SESSION['user_id'] . ':' . $random_token_string;
        $cookie_string_hash       = hash('sha256', $cookie_string_first_part . $this->settings['COOKIE_SECRET_KEY']);
        $cookie_string            = $cookie_string_first_part . ':' . $cookie_string_hash;
        //
        // set cookie $_COOKIE['rememberme']
        setcookie('rememberme', $cookie_string, time() + $this->settings['COOKIE_RUNTIME'], "/", $this->settings['COOKIE_DOMAIN']);
    }

    /**
     * Delete all data needed for remember me cookie connection on client and server side
     */
    public function deleteRememberMeCookie()
    {
        // if database connection opened and remember me cookie exist
        if (isset($_COOKIE['rememberme'])) {
            //
            // extract data from the cookie
            list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
            // check cookie hash validity
            if ($hash == hash('sha256', $user_id . ':' . $token . $this->settings['COOKIE_SECRET_KEY']) && !empty($token)) {
                // Reset rememberme token of this device
                (new \AlxMq)->req('user_connections[user_rememberme_token=* && user_id=*]:d', 'si', [(string)$token, (int)$_SESSION['user_id']]);
            }
        }
        // set the rememberme-cookie to ten years ago (3600sec * 365 days * 10).
        // that's obviously the best practice to kill a cookie via php
        // @see http://stackoverflow.com/a/686166/1114320
        setcookie('rememberme', false, time() - (3600 * 3650), '/', $this->settings['COOKIE_DOMAIN']);
    }

    /**
     * if user has an active session on the server
     *
     * 1. User want change his profile
     * 2. Logout (happen when user clicks logout button)
     */
    public function runSigninActions()
    {
        if (\User\Process\edit()) {
        }
        elseif (\User\Process\signout()) {
        }
        else {
        }
    }

    /**
     *
     * 2.  checking if user requested a password reset mail
     */
    public function runNoSignActions()
    {
        if (\User\Process\signin($this)) {
        }
        elseif (\User\Process\signup($this)) {
        }
        elseif (\User\Process\verify($this)) {
        }
        elseif (\User\Process\reset()) {
        }
        else {
        }
    }

    public function isAllowCurrentUserRegistration()
    {
        return (
            !$this->isUserLoggedIn() && $this->settings['ALLOW_USER_REGISTRATION']
            || $this->settings['ALLOW_ADMIN_TO_REGISTER_NEW_USER'] && $_SESSION['user_access_level'] == $this->ADMIN_LEVEL
        );
    }

    /**
     * Simply return the current state of the user's login
     * @return bool user's login status
     */
    public function isUserLoggedIn()
    {
        return (!empty($_SESSION['user_email']) && $_SESSION['user_logged_in'] == 1);
    }

    /**
     * Search into database for the user data of user_email specified as parameter
     *
     * @param $user_email
     *
     * @return object - user data as an object if existing user
     * @return bool - false if user_email is not found in the database
     */
    public function getUserDataFromEmail($user_email)
    {
        return (new \AlxMq)->req('user[email=*]?*', 's', [(string)$user_email]);
    }

    /**
     * @param $user_email
     *
     * @return array|bool|mysqli_result|mysqli_stmt|string
     */
    public function isUserExist($user_email)
    {
        $user_id = (new \AlxMq())->req('user[email=*]?id', 's', $user_email);
        return $user_id;
    }

    public function incrementLoginFails($user_email)
    {
        (new \AlxMq())->req('user[email=*]?user_failed_logins = user_failed_logins + 1, user_last_failed_login = *', 'si', [(string)$user_email, (int)time()]);
    }

    public function resetLoginFails($user_email)
    {
        (new \AlxMq())->req(
            'user[email=* && user_failed_logins != 0]?user_failed_logins = 0, user_last_failed_login = NULL',
            's', [(string)$user_email]
        );
    }

    public function deleteUser($user_email)
    {
        (new \AlxMq())->req('user[email=*]:d', 's', [(string)$user_email]);
    }

    /**
     * Gets the success state of the password-reset-link-validation.
     * @return boolean
     */
    public function isPasswordResetLinkValid()
    {
        return $this->password_reset_link_is_valid;
    }

    /**
     * Gets the success state of the password-reset action.
     * @return boolean
     */
    public function isPasswordResetSuccessful()
    {
        return $this->password_reset_was_successful;
    }

    /**
     * Get a Gravatar URL for the email address of connected user
     * Gravatar is the #1 (free) provider for email address based global avatar hosting.
     * The URL returns always a .jpg file !
     * For deeper info on the different parameter possibilities:
     * @see http://de.gravatar.com/site/implement/images/
     *
     * @param int|string $s Size in pixels, defaults to 50px [ 1 - 2048 ]
     * @param string     $d Default image set to use [ 404 | mm | identicon | monsterid | wavatar ]
     * @param string     $r Maximum rating (inclusive) [ g | pg | r | x ]
     * @source http://gravatar.com/site/implement/images/php/
     *
     * @return string
     */
    public function getGravatarImageUrl($s = 50, $d = 'mm', $r = 'g')
    {
        if ($_SESSION['user_email'] != '') {
            // the image url (on gravatar servers), will return in something like
            // http://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?s=80&d=mm&r=g
            // note: the url does NOT have something like .jpg
            return 'http://www.gravatar.com/avatar/' . md5(strtolower(trim($_SESSION['user_email']))) . "?s=$s&d=$d&r=$r&f=y";
        }
        else {
            return '';
        }
    }

    /**
     * @param $user_password_hash
     * @param $user_password_reset_hash
     * @param $user_email
     *
     * @return PDOStatement
     */
    public function writeUsersNewHashIntoDB($user_password_hash, $user_password_reset_hash, $user_email)
    {
        //
        // write users new hash into database
        return (new \AlxMq())->req(
            'user[email = * && user_password_reset_hash = *]?user_password_hash=*,user_password_reset_hash=NULL,user_password_reset_timestamp=NULL',
            'sss', [$user_email, $user_password_reset_hash, $user_password_hash]
        );
    }

    /**
     * @param $user_password_reset_hash
     * @param $temporary_timestamp
     * @param $user_email
     *
     * @return PDOStatement
     */
    public function writeUsersPasswordResetTempHashIntoDB($user_password_reset_hash, $temporary_timestamp, $user_email)
    {
        return (new \AlxMq())->req(
            'user[email=*]?user_password_reset_hash=*, user_password_reset_timestamp=*',
            'si', [$user_password_reset_hash, (int)$temporary_timestamp]
        );
    }

    public function removeUserActivationHash($user_email, $user_activation_hash)
    {
        return (new \AlxMq())->req(
            'user[email=*&&user_activation_hash=*]?user_activation_hash=NULL',
            'ss',
            [(string)trim($user_email), (string)$user_activation_hash]
        );
    }


    public function writeUsersActiveStatusIntoDB($user_email, $user_activation_hash, $isAutoActivationOnce = false)
    {
        $if($isAutoActivationOnce){
            $this->removeUserActivationHash($user_email, $user_activation_hash);
        }
        return (new \AlxMq())->req(
            'user[email=* && user_activation_hash=*]?user_active = 1',
            'ss',
            [(string)trim($user_email), (string)$user_activation_hash]
        );
    }


    /**
     * write new users data into database
     *
     * @param $user_name
     * @param $user_email
     * @param $user_password_hash
     * @param $user_activation_hash
     *
     * @return mixed
     */
    public function writeNewUserDataIntoDB($user_name, $user_email, $user_password_hash, $user_activation_hash)
    {
        // if user exist than try retrive his id
        if ($this->isUserExist($user_email)) {
            // Update password's hashes
            (new \AlxMq)->req(
                'user[id=*]?user_password_hash=*,user_activation_hash=*',
                'iss',
                [$user_id, $user_password_hash, $user_activation_hash]
            );
            return $user_id;
        }
        // Else Add new user and Return new user's id
        return (new \AlxMq)->req(
            'user[user_name=*,email=*,user_password_hash=*,user_activation_hash=*,user_registration_ip=*]>',
            'sssss',
            [$user_name, $user_email, $user_password_hash, $user_activation_hash, $_SERVER['REMOTE_ADDR']]
        );
    }

    /**
     *
     * @param $user_password_new
     *
     * @return bool
     */
    function writeNewPasswordIntoDB($user_password_new)
    {
        //
        // crypt the new user's password with the PHP 5.5's password_hash() function
        $user_password_hash = $this->getPasswordHash($user_password_new);
        //
        // write users new hash into database
        return $this->writeUserParamIntoDB($user_password_hash, 'user_password_hash');
    }

    /**
     * Crypt the $password with the PHP 5.5's password_hash()
     *
     * @param $password string
     *
     * @return bool|false|string - 60 character hash password string
     */
    public function getPasswordHash($password)
    {
        // check if we have a constant HASH_COST_FACTOR defined (in config/config.php),
        // if so: put the value into $hash_cost_factor, if not, make $hash_cost_factor = null
        $hash_cost_factor = $this->settings['HASH_COST_FACTOR'];
        // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 character hash string
        // the PASSWORD_DEFAULT constant is defined by the PHP 5.5, or if you are using PHP 5.3/5.4, by the password hashing
        // compatibility library. the third parameter looks a little bit shitty, but that's how those PHP 5.5 functions
        // want the parameter: as an array with, currently only used with 'cost' => XX.
        return password_hash($password, PASSWORD_DEFAULT, array('cost' => $hash_cost_factor));
    }

    /**
     * @param $paramValue
     * @param $paramNameUntrusted
     *
     * @return bool
     */
    function writeUserParamIntoDB($paramValue, $paramNameUntrusted)
    {
        $paramName = preg_replace('![^a-z0-9_-]!i', '', $paramNameUntrusted);
        $isSuccess = (new \AlxMq)->req("user[id=*]?{$paramName}=*", 'is', [(int)$_SESSION['user_id'], (string)$paramValue]);
        //
        if ($isSuccess) {
            $_SESSION[$paramName] = $paramValue;
            $this->messages[]     = '%MESSAGE_USER_PARAM_CHANGED_SUCCESSFULLY%' . $paramValue;
            return true;
        }
        else {
            $this->errors[] = '%MESSAGE_USER_PARAM_CHANGE_FAILED%';
        }
        return false;
    }

    /**
     * это ГОВНО :((
     * проект надо сдавать неделю назад...
     *
     * @param $user_email
     * @param $extra
     * @param $link
     *
     * @return mixed
     */
    public function writeNewExtraUserDataIntoDB($user_email, $extra, $link)
    {
        //
        // Insert extra data into linked table `origin_extra_{name}`
        // (link by `user_extra_{name}` table)
        if (!empty($extra) && is_array($extra))
            foreach ($extra as $extraName => $extraData) {
                $extraName      = preg_replace('![^a-z0-9\-_]!i', '', $extraName);
                $extraData      = preg_split('!,!', $extraData);
                $extraNameNames = [];
                $params         = []; // $params = [':user_email'=>$user_email];
                foreach ($extraData as $extraDataEl) {
                    $extraDataEl      = preg_split('!:!', $extraDataEl);
                    $extraNameNames[] = $extraDataEl[0];
                    $params[]         = $extraDataEl[1];
                }
                $extraNameNames = join(',', $extraNameNames);
                //
                // write new users data into database
                try {
                    (new \AlxMq())->req("origin_extra_{$extraName}[$extraNameNames]>", str_repeat('s', \Invntrm\true_count($params)), $params);
                } catch (Exception $e) {
                    \Invntrm\bugReport2('user login with extra', $e);
                }
                try {
                    (new \AlxMq())->req("user_extra_{$extraName}[user_email=*,origin_extra_{$extraName}_id=*]>", 'si', [$user_email]);
                } catch (Exception $e) {
                    \Invntrm\bugReport2('user login with extra', $e);
                }
            }

        //
        // Add link with `{name}` table
        // (link by `user_link_{name})` table
        try {
            if (!empty($extra) && is_array($extra))
                foreach ($link as $linkName => $linkValue) {
                    $linkName   = preg_replace('![^a-z0-9\-_]!i', '', $linkName);
                    $product_id = (new \AlxMq())->req("{$linkName}['$linkValue']?id");
                    (new \AlxMq())->req("user_link_{$linkName}[{$linkName}_id=*,user_email=*]>", 'is', [$product_id, $user_email]);
                }
        } catch (Exception $e) {
            \Invntrm\bugReport2('user login with links', $e);
        }
    }
}
