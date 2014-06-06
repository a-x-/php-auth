<?php
require_once 'User.php';

/**
 * handles the user login/logout/session
 * @author devplanete (2013 - 2014)
 * @author Panique (2012 - 2013)
 * @link https://github.com/devplanete/php-login-advanced
 * @license http://opensource.org/licenses/MIT MIT License
 */
class PHPLogin
{
    public $ADMIN_LEVEL = 255;
    /**
     * @var \PDO $db_connection The database connection
     */
    public $db_connection = null;
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
    public $errors = array();
    /**
     * @var array $messages Collection of success / neutral messages
     */
    public $messages = array();

    public $USER_NAME_VERIFICATION_REGEX = '';

    public $REQUEST_PATH = '';

    public $REQUEST_PATH_API = '';

    public $REQUEST_METHOD = '';

    /**
     * the function "__construct()" automatically starts whenever an object of this class is created,
     * you know, when you do "$login = new PHPLogin();"
     */
    public function __construct($configPath = '')
    {
        // check for minimum PHP version
        if (version_compare(PHP_VERSION, '5.3.7', '<')) {
            exit('Sorry, this script does not run on a PHP version smaller than 5.3.7 !');
        } else if (version_compare(PHP_VERSION, '5.5.0', '<')) {
            // if you are using PHP 5.3 or PHP 5.4 you have to include the password_api_compatibility_library.php
            // (this library adds the PHP 5.5 password hashing functions to older versions of PHP)
            require_once(__DIR__ . '/libraries/password_compatibility_library.php');
        }
        //
        // include the config
        require_once($configPath ? $configPath : __DIR__ . '/sample/config/config.php');
        //
        // include the to-be-used language. feel free to translate your project and include something else.
        // detection of the language for the current user/browser
        $user_lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
        // if translation file for the detected language doesn't exist, we use default english file
        $getTranslationFilePath = function ($lang) {
            return "$_SERVER[DOCUMENT_ROOT]/_data/translations/$lang.php";//$_SERVER[DOCUMENT_ROOT]/
        };
        if (!file_exists($getTranslationFilePath($user_lang))) {
            $user_lang = 'en';
        }
        require_once $getTranslationFilePath($user_lang);
        //
        $this->USER_NAME_VERIFICATION_REGEX = '/^[0-9 \-_' . (ALLOW_UTF8_USERNAMES ? '[:alpha:]' : 'a-z') . ']{2,64}$/iu';
        $this->REQUEST_PATH = (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        $this->REQUEST_PATH_API = @$_REQUEST['api_path'];
        $this->REQUEST_METHOD = strtolower($_SERVER['REQUEST_METHOD']);
        $GLOBALS['login'] = $this;
        //
        // create/read session
        @session_start();
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
    public function revealUserSession(){
        //
        // 1.
        // Login with session
        if(!empty($_SESSION['user_logged_in'])){
        }
        //
        // 2.
        // login with cookie
        if (isset($_COOKIE['rememberme'])) {
            $this->loginWithCookieData();
        }
        else {
            return false;
        }
        return true;
    }


    /**
     * if user has an active session on the server
     *
     * 1. User want change his profile
     * 2. Logout (happen when user clicks logout button)
     */
    public function runSigninActions ()
    {
        if(\User\Process\edit()){}
        elseif(\User\Process\signout()){}
        else {}
    }

    /**
     *
     * 2.  checking if user requested a password reset mail
     */
    public function runNoSignActions ()
    {
        if(\User\Process\signin($this)) {}
        elseif(\User\Process\signup($this)) {}
        elseif(\User\Process\verify($this)) {}
        elseif(\User\Process\reset()) {}
        else {}
    }

    public function isAllowCurrentUserRegistration()
    {
        return (
            !$this->isUserLoggedIn() && ALLOW_USER_REGISTRATION
            || ALLOW_ADMIN_TO_REGISTER_NEW_USER && $_SESSION['user_access_level'] == $this->ADMIN_LEVEL
        );
    }

    /**
     * Checks if database connection is opened. If not, then this method tries to open it.
     * @return bool Success status of the database connecting process
     */
    public function databaseConnection()
    {
        // if connection already exists
        if ($this->db_connection != null) {
            return true;
        } else {
            try {
                // Generate a database connection, using the PDO connector
                // Also important: We include the charset, as leaving it out seems to be a security issue:
                // @see http://wiki.hashphp.org/PDO_Tutorial_for_MySQL_Developers#Connecting_to_MySQL says:
                // "Adding the charset to the DSN is very important for security reasons"
                $this->db_connection = new PDO('mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8', DB_USER, DB_PASS);
                return true;
            } catch (PDOException $e) {
                $this->errors[] = MESSAGE_DATABASE_ERROR . $e->getMessage();
            }
        }
        // default return
        return false;
    }

    /**
     * Search into database for the user data of user_email specified as parameter
     * @param $user_email
     * @return object - user data as an object if existing user
     * @return bool - false if user_email is not found in the database
     */
    public function getUserDataFromEmail($user_email)
    {
        // if database connection opened
        if ($this->databaseConnection()) {
            // database query, getting all the info of the selected user
            $query_user = $this->db_connection->prepare('SELECT * FROM user WHERE email = :user_email');
            $query_user->bindValue(':user_email', $user_email, PDO::PARAM_STR);
            $query_user->execute();
            // get result row (as an object)
            return $query_user->fetchObject();
        } else {
            return false;
        }
    }

    /**
     * Create a PHPMailer Object with configuration of config.php
     * @return PHPMailer Object
     */
    public function getPHPMailerObject()
    {
        require_once(__DIR__ . '/libraries/PHPMailer.php');
        $mail = new PHPMailer;

        // please look into the config/config.php for much more info on how to use this!
        // use SMTP or use mail()
        if (EMAIL_USE_SMTP) {
            require_once(__DIR__ . '/libraries/SMTP.php');
            // Set mailer to use SMTP
            $mail->IsSMTP();
            if (EMAIL_BODY_TYPE == 'html')
                $mail->isHTML();
            //useful for debugging, shows full SMTP errors
            //$mail->SMTPDebug = 1; // debugging: 1 = errors and messages, 2 = messages only
            // Enable SMTP authentication
            $mail->SMTPAuth = EMAIL_SMTP_AUTH;
            // Enable encryption, usually SSL/TLS
            if (defined(EMAIL_SMTP_ENCRYPTION)) {
                $mail->SMTPSecure = EMAIL_SMTP_ENCRYPTION;
            }
            // Specify host server
            $mail->Host = EMAIL_SMTP_HOST;
            $mail->Username = EMAIL_SMTP_USERNAME;
            $mail->Password = EMAIL_SMTP_PASSWORD;
            $mail->Port = EMAIL_SMTP_PORT;
        } else {
            $mail->IsMail();
        }
        return $mail;
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
            if ($hash == hash('sha256', $user_id . ':' . $token . COOKIE_SECRET_KEY) && !empty($token)) {
                // cookie looks good, try to select corresponding user
                if ($this->databaseConnection()) {
                    // get real token from database (and all other data)
                    $sth = $this->db_connection->prepare(
                        "SELECT
                           user.user_id,
                           user.user_name,
                           user.email,
                           user.user_access_level
                        FROM user_connections
                           LEFT JOIN user u ON uc.user_id = u.user_id
                        WHERE
                           uc.user_id = :user_id
                            AND uc.user_rememberme_token = :user_rememberme_token
                            AND uc.user_rememberme_token IS NOT NULL"
                    );
                    $sth->bindValue(':user_id', $user_id, PDO::PARAM_INT);
                    $sth->bindValue(':user_rememberme_token', $token, PDO::PARAM_STR);
                    $sth->execute();
                    // get result row (as an object)
                    $result_row = $sth->fetchObject();

                    if (isset($result_row->user_id)) {
                        $this->writeUserDataIntoSession($result_row); // write user data into PHP SESSION [a file on your server]

                        // Cookie token usable only once
                        $this->newRememberMeCookie($token);
                        return true;
                    }
                }
            }
            // A cookie has been used but is not valid... we delete it
            $this->deleteRememberMeCookie();
            $this->errors[] = MESSAGE_COOKIE_INVALID;
        }
        return false;
    }

    /**
     * write user data into PHP SESSION [a file on your server]
     */
    public function writeUserDataIntoSession($user_object)
    {
        $user_object = (array)$user_object;
        $_SESSION['user_id'] = $user_object['user_id'];
        $_SESSION['user_name'] = $user_object['user_name'];
        $_SESSION['user_email'] = $user_object['email'];
        $_SESSION['user_access_level'] = $user_object['user_access_level'];
        $_SESSION['user_logged_in'] = 1;
    }

    public function incrementLoginFails ($user_email)
    {
        $sth = $this->db_connection->prepare(
            'UPDATE user SET
                user_failed_logins = user_failed_logins+1,
                user_last_failed_login = :user_last_failed_login
             WHERE email = :user_email'
        );
        $sth->execute(array(':user_email' => $user_email, ':user_last_failed_login' => time()));
    }

    public function resetLoginFails ($user_email)
    {
        $sth = $this->db_connection->prepare(
            'UPDATE user SET user_failed_logins = 0, user_last_failed_login = NULL
            WHERE user_email = :user_email AND user_failed_logins != 0'
        );
        $sth->execute(array(':user_email' => $user_email));
    }

    /**
     * Create all data needed for remember me cookie connection on client and server side
     */
    public function newRememberMeCookie($current_rememberme_token = '')
    {
        // if database connection opened
        if ($this->databaseConnection()) {
            // generate 64 char random string and store it in current user data
            $random_token_string = hash('sha256', mt_rand());

            // record the new token for this user/device
            if ($current_rememberme_token == '') {
                $sth = $this->db_connection->prepare("INSERT INTO user_connections (user_id, user_rememberme_token, user_login_agent, user_login_ip, user_login_datetime, user_last_visit) VALUES (:user_id, :user_rememberme_token, :user_login_agent, :user_login_ip, now(), now())");
                $sth->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
                $sth->bindValue(':user_rememberme_token', $random_token_string, PDO::PARAM_STR);
                $sth->bindValue(':user_login_agent', $_SERVER['HTTP_USER_AGENT'], PDO::PARAM_STR);
                $sth->bindValue(':user_login_ip', $_SERVER['REMOTE_ADDR'], PDO::PARAM_STR);
                $sth->execute();
            } // update current rememberme token hash by a new one
            else {
                $sth = $this->db_connection->prepare("UPDATE user_connections SET user_rememberme_token = :new_token, user_last_visit=now(), user_last_visit_agent = :user_agent WHERE user_id = :user_id AND user_rememberme_token = :old_token");
                $sth->bindValue(':new_token', $random_token_string, PDO::PARAM_STR);
                $sth->bindValue(':user_agent', $_SERVER['HTTP_USER_AGENT'], PDO::PARAM_STR);
                $sth->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
                $sth->bindValue(':old_token', $current_rememberme_token, PDO::PARAM_STR);
                $sth->execute();
            }

            // generate cookie string that consists of userid, random string and combined hash of both
            $cookie_string_first_part = $_SESSION['user_id'] . ':' . $random_token_string;
            $cookie_string_hash = hash('sha256', $cookie_string_first_part . COOKIE_SECRET_KEY);
            $cookie_string = $cookie_string_first_part . ':' . $cookie_string_hash;

            // set cookie
            setcookie('rememberme', $cookie_string, time() + COOKIE_RUNTIME, "/", COOKIE_DOMAIN);
        }
    }

    /**
     * Simply return the current state of the user's login
     * @return bool user's login status
     */
    public function isUserLoggedIn()
    {
        return (!empty($_SESSION['user_email']) && $_SESSION['user_logged_in'] == 1);
    }

    public function deleteUser($user_email)
    {
        $query_delete_user = $this->db_connection->prepare('DELETE FROM user WHERE email=:user_email');
        $query_delete_user->bindValue(':user_email', $user_email, PDO::PARAM_INT);
        $query_delete_user->execute();
    }

    /**
     * Delete all data needed for remember me cookie connection on client and server side
     */
    public function deleteRememberMeCookie()
    {
        // if database connection opened and remember me cookie exist
        if ($this->databaseConnection() && isset($_COOKIE['rememberme'])) {
            //
            // extract data from the cookie
            list ($user_id, $token, $hash) = explode(':', $_COOKIE['rememberme']);
            // check cookie hash validity
            if ($hash == hash('sha256', $user_id . ':' . $token . COOKIE_SECRET_KEY) && !empty($token)) {
                // Reset rememberme token of this device
                $sth = $this->db_connection->prepare("DELETE FROM user_connections WHERE user_rememberme_token = :user_rememberme_token AND user_id = :user_id");
                $sth->bindValue(':user_id', $_SESSION['user_id'], PDO::PARAM_INT);
                $sth->bindValue(':user_rememberme_token', $token, PDO::PARAM_STR);
                $sth->execute();
            }
        }
        // set the rememberme-cookie to ten years ago (3600sec * 365 days * 10).
        // that's obviously the best practice to kill a cookie via php
        // @see http://stackoverflow.com/a/686166/1114320
        setcookie('rememberme', false, time() - (3600 * 3650), '/', COOKIE_DOMAIN);
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
     * @param string $d Default image set to use [ 404 | mm | identicon | monsterid | wavatar ]
     * @param string $r Maximum rating (inclusive) [ g | pg | r | x ]
     * @source http://gravatar.com/site/implement/images/php/
     * @return string
     */
    public function getGravatarImageUrl($s = 50, $d = 'mm', $r = 'g')
    {
        if ($_SESSION['user_email'] != '') {
            // the image url (on gravatar servers), will return in something like
            // http://www.gravatar.com/avatar/205e460b479e2e5b48aec07710c08d50?s=80&d=mm&r=g
            // note: the url does NOT have something like .jpg
            return 'http://www.gravatar.com/avatar/' . md5(strtolower(trim($_SESSION['user_email']))) . "?s=$s&d=$d&r=$r&f=y";
        } else {
            return '';
        }
    }

    /**
     * @param $user_password_hash
     * @param $user_password_reset_hash
     * @param $user_email
     * @return PDOStatement
     */
    public function writeUsersNewHashIntoDB($user_password_hash, $user_password_reset_hash, $user_email)
    {
        //
        // write users new hash into database
        $query_update = $this->db_connection->prepare(
            'UPDATE user SET
               user_password_hash = :user_password_hash,user_password_reset_hash = NULL, user_password_reset_timestamp = NULL
             WHERE email = :user_email AND user_password_reset_hash = :user_password_reset_hash'
        );
        $query_update->bindValue(':user_password_hash', $user_password_hash, PDO::PARAM_STR);
        $query_update->bindValue(':user_password_reset_hash', $user_password_reset_hash, PDO::PARAM_STR);
        $query_update->bindValue(':user_email', $user_email, PDO::PARAM_STR);
        $query_update->execute();
        return $query_update;
    }

    /**
     * @param $user_password_reset_hash
     * @param $temporary_timestamp
     * @param $user_email
     * @return PDOStatement
     */
    public function writeUsersPasswordResetTempHashIntoDB($user_password_reset_hash, $temporary_timestamp, $user_email)
    {
        $query_update = $this->db_connection->prepare(
            'UPDATE user SET
               user_password_reset_hash = :user_password_reset_hash,
               user_password_reset_timestamp = :user_password_reset_timestamp
             WHERE email = :user_email'
        );
        $query_update->bindValue(':user_password_reset_hash', $user_password_reset_hash, PDO::PARAM_STR);
        $query_update->bindValue(':user_password_reset_timestamp', $temporary_timestamp, PDO::PARAM_INT);
        $query_update->bindValue(':user_email', $user_email, PDO::PARAM_STR);
        $query_update->execute();
        return $query_update;
    }

    public function writeUsersActiveStatusIntoDB($user_email, $user_activation_hash)
    {
        $query_update_user = $this->db_connection->prepare(
            'UPDATE user SET
                user_active = 1, user_activation_hash = NULL
             WHERE email = :user_email AND user_activation_hash = :user_activation_hash'
        );
        $query_update_user->bindValue(':user_email', trim($user_email), PDO::PARAM_STR);
        $query_update_user->bindValue(':user_activation_hash', $user_activation_hash, PDO::PARAM_STR);
        $query_update_user->execute();
        return $query_update_user;
    }

    /**
     * @param $user_name
     * @param $user_email
     * @param $user_password_hash
     * @param $user_activation_hash
     * @internal param $login
     * @return mixed
     */
    public function writeNewUserDataIntoDB($user_name, $user_email, $user_password_hash, $user_activation_hash)
    {
        // write new users data into database
        require_once "$_SERVER[DOCUMENT_ROOT]/vendor/a-x-/invntrm-common-php/Mq.php";
        $mq = new \AlxMq();
        // Is user exist
        $user_id = $mq->req('user[email=*]?user_id','s',$user_email);
        // if user exist
        if($user_id) {
            // Update password's hashes
            $mq->req(
                'user[user_id=*]?user_password_hash=*,user_activation_hash=*',
                'iss',
                [$user_id, $user_password_hash, $user_activation_hash]
            );
        }
        // Return user id
        return (!$user_id) ? $mq->req(
            'user[user_name=*,email=*,user_password_hash=*,user_activation_hash=*,user_registration_ip=*]>'
            ,'sssss'
            ,[$user_name, $user_email, $user_password_hash, $user_activation_hash,$_SERVER['REMOTE_ADDR']]
        ) : $user_id;
    }

    /**
     * Crypt the $password with the PHP 5.5's password_hash()
     * @param $password string
     * @return bool|false|string - 60 character hash password string
     */
    public function getPasswordHash($password)
    {
        // check if we have a constant HASH_COST_FACTOR defined (in config/config.php),
        // if so: put the value into $hash_cost_factor, if not, make $hash_cost_factor = null
        $hash_cost_factor = (defined('HASH_COST_FACTOR') ? HASH_COST_FACTOR : null);
        // crypt the user's password with the PHP 5.5's password_hash() function, results in a 60 character hash string
        // the PASSWORD_DEFAULT constant is defined by the PHP 5.5, or if you are using PHP 5.3/5.4, by the password hashing
        // compatibility library. the third parameter looks a little bit shitty, but that's how those PHP 5.5 functions
        // want the parameter: as an array with, currently only used with 'cost' => XX.
        return password_hash($password, PASSWORD_DEFAULT, array('cost' => $hash_cost_factor));
    }

    /**
     * @param $paramValue
     * @param $paramNameUntrusted
     * @return bool
     */
    function writeUserParamIntoDB($paramValue, $paramNameUntrusted)
    {
        $paramName = preg_replace('![^a-z0-9_-]!i', '', $paramNameUntrusted);
        $query_edit_user_name = $this->db_connection->prepare(
            "UPDATE user SET $paramName = :$paramName WHERE user_id = :user_id"
        );
        $query_edit_user_name->execute([":$paramName"=>$paramValue,':user_id'=>$_SESSION['user_id']]);
        //
        if ($query_edit_user_name->rowCount()) {
            $_SESSION[$paramName] = $paramValue;
            $this->messages[] = MESSAGE_USER_PARAM_CHANGED_SUCCESSFULLY . $paramValue;
            return true;
        } else {
            $this->errors[] = MESSAGE_USER_PARAM_CHANGE_FAILED;
        }
        return false;
    }

    /**
     *
     * @param $user_password_new
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
     * это ГОВНО :((
     * проект надо сдавать неделю назад...
     * @param $user_email
     * @param $extra
     * @param $link
     * @return mixed
     */
    public function writeNewExtraUserDataIntoDB($user_email, $extra, $link)
    {
        require_once "$_SERVER[DOCUMENT_ROOT]/vendor/a-x-/invntrm-common-php/Mq.php";
        //
        // Insert extra data into linked table `origin_extra_{name}`
        // (link by `user_extra_{name}` table)
        foreach($extra as $extraName => $extraData) {
            $extraName = preg_replace('![^a-z0-9\-_]!i','',$extraName);
            $extraData = preg_split('!,!',$extraData);
            $extraNameNames = []; $params = [];// $params = [':user_email'=>$user_email];
            foreach($extraData as $extraDataEl) {
                $extraDataEl = preg_split('!:!',$extraDataEl);
                $extraNameNames[]= $extraDataEl[0];
                $params[]=$extraDataEl[1];
            }
            $extraNameNames = join(',',$extraNameNames);
            //
            // write new users data into database
            (new \AlxMq())->req("origin_extra_{$extraName}[$extraNameNames]>",str_repeat('s',\Invntrm\true_count($params)),$params);
            (new \AlxMq())->req("user_extra_{$extraName}[user_email=*,origin_extra_{$extraName}_id=*]>",'si',[$user_email]);
        }
        //
        // Add link with `{name}` table
        // (link by `user_link_{name})` table
        foreach($link as $linkName => $linkValue) {
            $linkName = preg_replace('![^a-z0-9\-_]!i','',$linkName);
            $product_id = (new \AlxMq())->req("{$linkName}['$linkValue']?id");
            (new \AlxMq())->req("user_link_{$linkName}[{$linkName}_id=*,user_email=*]>",'is',[$product_id,$user_email]);
        }
    }
}