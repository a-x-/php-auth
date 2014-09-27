<?php
/**
 * @file AB-STORE / test.php
 * Created: 28.05.14 / 23:06
 *
 * Front open functions.
 */
namespace User {
    //    require_once __DIR__ . "/vendor/autoload.php";
    require_once __DIR__ . "/UserCommon.php";
    require_once __DIR__ . "/UserModel.php";
    require_once __DIR__ . "/UserInterface.php";

    /**
     */
    function signout()
    {
        $is_success = \User\Common\delete_cookie_session();
        return \User\Common\get_exit_result($is_success);
    }

    /**
     * Get user properties collection or specified property
     * @param null|string $property
     */
    function get($user_identifier, $id_name = 'id', $property = '*')
    {
        return \User\Common\Model\get_user_by_id($user_identifier, $id_name, $property);
    }

    function is_session_valid($user_id, $token)
    {
        return \User\Common\Model\is_user_session_valid($user_id, $token);
    }
} // User

namespace User\Signin {

    /**
     * Logs in with the data provided in $_POST, coming from the login form.
     * Testing: http -fb post 'http://testdev.brandis.club/api/account/' 'user_email=goal.inv@ya.ru'
     *
     * @param      $user_email
     * @param      $user_password
     * @param      $is_rememberme
     * @param bool $isAutoSignin
     *
     * @return array
     */
    function check_post($user_email, $user_password, $is_rememberme, $isAutoSignin = false)
    {
        if ($isAutoSignin || \User\Common\Signin\check_post($user_email, $user_password)) {
            \User\Common\Signin\ok($user_email, $is_rememberme, $user_password);
        }
        return \User\Common\get_exit_result();
    }
}

namespace User\Signup {
    use User\Common\Single;

    /**
     * 1.
     * handles the entire registration process. checks all error possibilities, and creates a new user in the database if
     * everything is fine
     *
     * @param $user_email
     * @param $optional_fields
     *
     * @return array
     *
     * @internal param $user_password
     * @internal param $user_password_repeat
     * @internal param $captcha
     */
    function check_post($user_email, $optional_fields)
    {
        $memo = Single::getInstance();
        if (!\User\Common\is_allow_signup()) return ['error' => 'Sign up is not allowed now for you'];
        if (empty($optional_fields)) $optional_fields = [];
        // prevent database flooding
        $user_email           = trim($user_email);
        $captcha              = (isset($optional_fields['captcha'])) ? trim($optional_fields['captcha']) : '';
        $user_password_repeat = (isset($optional_fields['user_password_repeat'])) ? trim($optional_fields['user_password_repeat']) : '';
        $user_password_new    = (isset($optional_fields['user_password_new'])) ? trim($optional_fields['user_password_new']) : '';
        //
        // check provided data validity
        if (!$memo->settings['ALLOW_NO_CAPTCHA'] && strtolower($captcha) != strtolower($_SESSION['captcha'])) {
            $memo->add_error('%MESSAGE_CAPTCHA_WRONG%');
        }
        if (!$memo->settings['ALLOW_NO_PASSWORD'] && empty($user_password_new) || !$memo->settings['ALLOW_NO_PASSWORD_RETYPE'] && empty($user_password_repeat)) {
            $memo->add_error('%MESSAGE_PASSWORD_EMPTY%');
        }
        if (!$memo->settings['ALLOW_NO_PASSWORD_RETYPE'] && $user_password_new !== $user_password_repeat) {
            $memo->add_error('%MESSAGE_PASSWORD_BAD_CONFIRM%');
        }
        if (!$memo->settings['ALLOW_NO_PASSWORD'] && strlen($user_password_new) < 6) {
            $memo->add_error('%MESSAGE_PASSWORD_TOO_SHORT%');
        }
        if (empty($user_email)) {
            $memo->add_error('%MESSAGE_EMAIL_EMPTY%');
        }
        if (strlen($user_email) > 254) {
            $memo->add_error('%MESSAGE_EMAIL_TOO_LONG%');
        }
        if (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
            $memo->add_error('%MESSAGE_EMAIL_INVALID%');
        }
        //
        // Check for errors
        if (\Invntrm\true_count($memo->get_errors_collection())) {
            return \User\Common\get_exit_result();
        }
        //
        // finally if all the above checks are ok
        // if email already in the database
        if (\User\Common\Model\is_user_exist($user_email)) {
            $memo->add_error('%MESSAGE_EMAIL_ALREADY_EXISTS%');
            return \User\Common\get_exit_result();
        }
        //
        // Finally Finally. Ok user can be create
        $user_id = \User\Common\Signup\add_user($user_email, $user_password_new);
        if (!$user_id) {
            $memo->add_error('%MESSAGE_REGISTRATION_FAILED%');
            return \User\Common\get_exit_result();
        }
        //
        // Finally Finally Finally. Ok, user created, let's send notify
        $user_activation_hash = \User\Common\Model\init_activation($user_email);
        // send a verification email
        try {
            $isVerifyMailSent = \User\Common\Signup\send_mail_verify($user_email, $user_activation_hash, $memo->settings['MAIL_VERIFY_FN']);
        } catch (\Exception $e) {
            \Invntrm\bugReport2('signup,mail_verify', $e);
            $isVerifyMailSent = false;
        }
        if ($isVerifyMailSent) {
            // Mail has been send successfully
            //                        $memo->add_message('%MESSAGE_VERIFICATION_MAIL_SENT%');
        } else {
            // delete this users account immediately, as we could not send a verification email
            \User\Common\Model\delete($user_email);
            $memo->add_error('%MESSAGE_VERIFICATION_MAIL_ERROR%');
        }
        return \User\Common\get_exit_result(["user" => ["id" => $user_id]]);
    }

    /**
     * 3.
     * checks the id/verification code combination and set the user's activation status to true (=1) in the database
     *
     * @param $user_id
     * @param $user_activation_hash
     *
     * @return array
     */
    function check_verify($user_id, $user_activation_hash)
    {
        $memo = Single::getInstance();
        try {
            $user_email = \User\Common\Model\get_user_by_id($user_id)['email'];
        } catch (\Exception $e) {
            \Invntrm\bugReport2('signup,verify,check', $e);
        }
        if (empty($user_activation_hash)) {
            $memo->add_error('%MESSAGE_LINK_PARAMETER_EMPTY%');
        }
        if (empty($user_email)) {
            $memo->add_error('%MESSAGE_EMAIL_EMPTY%');
        }
        // try to update user with specified information
        $query_update_user = \User\Common\Model\set_active($user_email, $user_activation_hash);
        //
        if ($query_update_user) {
            if ($memo->settings['ALLOW_AUTO_SIGNIN_AFTER_VERIFY']) {
                \User\Common\Signin\ok($user_email, $memo->settings['ALLOW_REMEMBERME_BY_DEFAULT']);
            }
            // Registration activation successful
            //            $memo->add_message('%MESSAGE_REGISTRATION_ACTIVATION_SUCCESSFUL%');
            return \User\Common\get_exit_result();
            // header('Location: ' . $memo->settings['BASE_VIEW_ENDPOINT'] . '/?message=%MESSAGE_REGISTRATION_ACTIVATION_SUCCESSFUL%');
        } else {
            // send bug report
            \Invntrm\bugReport2(
                'PHPLogin::check_verify', 'verification finish stage failed on the DB recording: '
                . \Invntrm\varDumpRet($query_update_user)
            );
            // delete this users account immediately, as we could not send a verification email
            // uncomment in production
            \User\Common\Model\delete($user_email);
            $memo->add_error('%MESSAGE_REGISTRATION_ACTIVATION_NOT_SUCCESSFUL%');
            return \User\Common\get_exit_result();
            // header('Location: ' . $memo->settings['BASE_VIEW_ENDPOINT'] . '/signup/?error=%MESSAGE_REGISTRATION_ACTIVATION_NOT_SUCCESSFUL%');
        }
    }
}

/**
 * Reset password
 */
namespace User\Reset {
    use User\Common\Single;

    /**
     * 1.
     * Sets a random token into the database (that will verify the user when he/she comes back via the link
     * in the email) and sends the according email.
     */
    function check_post($user_email)
    {
        $is_success = false;
        $memo       = Single::getInstance();
        $user_email = trim($user_email);
        // send a mail to the user, containing a link with that token hash string
        if (\User\Common\Reset\check_post($user_email)) {
            $is_success = \User\Common\Reset\send_mail_verify($user_email, $memo->settings['MAIL_RESET_PASSWORD_FN']);
        }
        return \User\Common\get_exit_result($is_success);
    }


    /**
     * 3.
     * Checks if the verification string in the account verification mail is valid and matches to the user.
     *
     * @param $user_email
     * @param $verification_code
     *
     * @param $password
     * @param $password_repeat
     *
     * @return bool
     */
    function check_verify($user_email, $verification_code, $password, $password_repeat = null)
    {
        $is_success = false;
        $memo       = Single::getInstance();
        $user_email = trim($user_email);
        if (empty($user_email) || empty($verification_code)) {
            $memo->add_error('%MESSAGE_LINK_PARAMETER_EMPTY%');
        } else {
            if (\User\Common\Reset\check_verify($user_email, $verification_code)) {
                $is_success = \User\Common\Reset\set_password(
                    $user_email,
                    $verification_code,
                    $password,
                    $password_repeat
                );
                if ($memo->settings['ALLOW_AUTO_SIGNIN_AFTER_VERIFY'] === true) {
                    try {
                        // sign in w/o addition checking
                        \User\Signin\check_post($user_email, $password, $memo->settings['ALLOW_REMEMBERME_BY_DEFAULT'], true);
                    } catch (\Exception $e) {
                        \Invntrm\bugReport2('reset password,auto signin', $e);
                    }
                }
            }
        }
        return \User\Common\get_exit_result($is_success);
    }
}

/**
 * @deprecated
 */
namespace User\Edit {
    use User\Common\Single;

    //    /**
    //     * @deprecated
    //     * @todo довести
    //     * Edit the user's name, provided in the editing form
    //     *
    //     * @param $user_name
    //     */
    //    function name($user_name)
    //    {
    //        $memo = Single::getInstance();
    //        // prevent database flooding
    //        $user_name = substr(trim($user_name), 0, 64);
    //        //
    //        if (!empty($user_name) && $user_name == $_SESSION['user_name']) {
    //            $memo->add_error('%MESSAGE_USERNAME_SAME_LIKE_OLD_ONE%');
    //            // username cannot be empty and must be <...> and 2-64 characters
    //        }
    //        elseif (empty($user_name) || !preg_match($memo::$USER_NAME_VERIFICATION_REGEX, $user_name)) {
    //            $memo->add_error('%MESSAGE_USERNAME_INVALID%');
    //        }
    //        else {
    //            // write user's new data into database
    //            \User\Common\Model\set_param($user_name, 'user_name');
    //        }
    //    }


    /**
     * @deprecated
     * @todo довести
     * @todo убрать session
     * Edit the user's email, provided in the editing form
     *
     * @param $user_id
     * @param $user_email
     */
    function email($user_id, $user_email)
    {
        $memo = Single::getInstance();
        // prevent database flooding
        $user_email = substr(trim($user_email), 0, 254);
        //
        if (!empty($user_email) && $user_email == $_SESSION["user_email"]) {
            $memo->add_error('%MESSAGE_EMAIL_SAME_LIKE_OLD_ONE%');
            // user mail cannot be empty and must be in email format
        } elseif (empty($user_email) || !filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
            $memo->add_error('%MESSAGE_EMAIL_INVALID%');
        } else {
            // if this email exists
            if (\User\Common\Model\is_user_exist($user_email)) {
                $memo->add_error('%MESSAGE_EMAIL_ALREADY_EXISTS%');
            } else {
                //
                // write users new data into database
                \User\Common\Model\set_param($user_id, 'user_email', $user_email);
            }
        }
    }

    /**
     * @deprecated
     * @todo довести
     * Edit the user's password, provided in the editing form
     *
     * @param $user_id
     * @param $password_current
     * @param $password_new_repeat
     * @param $password_new
     */
    function password($user_id, $password_current, $password_new_repeat, $password_new)
    {
        $memo = Single::getInstance();
        if (empty($password_new) || empty($password_new_repeat) || empty($password_current)) {
            $memo->add_error('%MESSAGE_PASSWORD_EMPTY%');
            // is the repeat password identical to password
        } elseif ($password_new !== $password_new_repeat) {
            $memo->add_error('%MESSAGE_PASSWORD_BAD_CONFIRM%');
            // password need to have a minimum length of 6 characters
        } elseif (strlen($password_new) < 6) {
            $memo->add_error('%MESSAGE_PASSWORD_TOO_SHORT%');
            // all the above tests are ok
        } else {
            // database query, getting hash of currently logged in user (to check with just provided password)
            $user_object = \User\Common\Model\get_user_by_id($user_id);
            // if this user exists
            if (!isset($user_object['user_password_hash'])) {
                // was '%MESSAGE_USER_DOES_NOT_EXIST%' before, but has changed
                // to prevent potential attackers showing if the user exists
                $memo->add_error('%MESSAGE_USER_PARAM_CHANGE_FAILED%');
            } // using PHP 5.5's password_verify() function to check if the provided passwords fits to the hash of that user's password
            elseif (!password_verify($password_current, $user_object['user_password_hash'])) {
                $memo->add_error('%MESSAGE_OLD_PASSWORD_WRONG%');
            } else {
                \User\Common\Model\set_password($user_id, $password_new);
            }

        }
    }

}

namespace User\Token {
    use User\Common\Single;

    function grant($user_id, $name, $args_line_input, $time, $granter, $code)
    {
        $memo = Single::getInstance();
        if (!\User\Common\Token\is_granter_correct_tmp($granter, $code))
            return \User\Common\get_exit_result();
        $token        = (new \AlxMq())->req('token[name=*]?id, args_default', 's', [$name]);
        $token_id     = $token['id'];
        $args_default = json_decode($token['args_default'], true);
        $args         = is_array($args_line_input) ? $args_line_input : json_decode($args_line_input, true);
//        $is_exist = !!(new \AlxMq())->req('user_map_token[token_id=* && user_id=*]?count', 'ii', [(int)$token_id, (int)$user_id]);
//        if ($is_exist)
//            return \User\Common\get_exit_result('already exist');
        //
        $args_end  = array_merge($args_default, $args);
        $args_line = json_encode($args_end, JSON_UNESCAPED_UNICODE);
        try {
            $time ? (new \AlxMq())->req('user_map_token[token_id=*, args=*, user_id=*, time=*]>', 'isii', [(int)$token_id, $args_line, (int)$user_id, (int)$time])
                : (new \AlxMq())->req('user_map_token[token_id=*, args=*, user_id=*]>', 'isi', [(int)$token_id, $args_line, (int)$user_id]);
        } catch (\Exception $e) {
            \Invntrm\bugReport2('user,token,grant', $e);
            $memo->add_error('%MESSAGE_UNKNOWN_ERROR%');
        }
        return \User\Common\get_exit_result(true);
    }

    function revoke($user_id, $grant_id, $granter, $code)
    {
        $memo = Single::getInstance();
        if (!\User\Common\Token\is_granter_correct_tmp($granter, $code))
            return \User\Common\get_exit_result();
        try {
            (new \AlxMq())->req('user_map_token[id=*]:d', 'i', [(int)$grant_id]);
        } catch (\Exception $e) {
            \Invntrm\bugReport2('user,token,revoke', $e);
            $memo->add_error('%MESSAGE_UNKNOWN_ERROR%');
        }
        return \User\Common\get_exit_result(true);
    }

    function get($user_id, $token_name = null)
    {
        $fields = 'token.*, args, datetime, expiration';
        $condition = 'user_map_token_extended.is_active = 1';
        $feed = $token_name
            ? (new \AlxMq())->req("user_map_token_extended[user_id=*&&token.name=*&&$condition]?$fields", 'is', [(int)$user_id, $token_name], \Mq_Mode::RAW_DATA)
            : (new \AlxMq())->req("user_map_token_extended[user_id=*&&$condition]?$fields", 'i', [(int)$user_id], \Mq_Mode::RAW_DATA);
        if (!$feed) $feed = [];
        $feed = array_map(function ($token) {
            $args_default = json_decode($token['args_default'], true);
            $args = json_decode($token['args'], true);
            $token['args'] = array_merge($args_default, $args);
            unset($token['args_default']);
            return $token;
        }, $feed);
        return \User\Common\get_exit_result($feed);
    }
}