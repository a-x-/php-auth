<?php
/**
 * @file AB-STORE / UserModel.php
 * Created: 10.09.14 / 18:38
 */

namespace User {

}

namespace User\Common {

}

namespace User\Common\Model {
    use User\Common\Single;

    /**
     * Search into database for the user data of user_email specified as parameter
     *
     * @param $user_email
     *
     * @return object - user data as an object if existing user
     * @return bool - false if user_email is not found in the database
     */
    function get_user_by_email($user_email)
    {
        return (new \AlxMq)->req('user[email=*]?*', 's', [(string)$user_email]);
    }

    /**
     * @param $user_email
     *
     * @return int user_id
     */
    function is_user_exist($user_email)
    {
        return (int)((new \AlxMq())->req('user[email=*]?id', 's', $user_email));
    }

    function increment_signin_fails($user_email)
    {
        (new \AlxMq())->req('user[email=*]?user_failed_logins = user_failed_logins + 1, user_last_failed_login = *', 'si', [(string)$user_email, (int)time()]);
    }

    function reset_signin_fails($user_email)
    {
        (new \AlxMq())->req(
            'user[email=* && user_failed_logins != 0]?user_failed_logins = 0, user_last_failed_login = NULL',
            's', [(string)$user_email]
        );
    }

    function delete($user_email)
    {
        (new \AlxMq())->req('user[email=*]:d', 's', [(string)$user_email]);
    }

    /**
     * @param $user_password_hash
     * @param $user_password_reset_hash
     * @param $user_email
     *
     * @return array
     */
    function reset_password($user_password_hash, $user_password_reset_hash, $user_email)
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
     * @return array
     */
    function set_reset_password_request($user_password_reset_hash, $temporary_timestamp, $user_email)
    {
        return (new \AlxMq())->req(
            'user[email=*]?user_password_reset_hash=*, user_password_reset_timestamp=*',
            'ssi', [$user_email, $user_password_reset_hash, (int)$temporary_timestamp]
        );
    }

    function set_nonactive($user_email, $user_activation_hash)
    {
        return (new \AlxMq())->req(
            'user[email=*&&user_activation_hash=*]?user_activation_hash=NULL',
            'ss',
            [(string)trim($user_email), (string)$user_activation_hash]
        );
    }


    function set_active($user_email, $user_activation_hash, $isAutoActivationOnce = false)
    {
        if ($isAutoActivationOnce) {
            $this->set_nonactive($user_email, $user_activation_hash);
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
     *
     * @internal param $user_activation_hash
     *
     * @return mixed
     */
    function set_data($user_name, $user_email, $user_password_hash)
    {
        // if user exist than try update his password and retrieve his id
        if (\User\Common\Model\is_user_exist($user_email)) {
            // Update password's hashes
            $user_id = (new \AlxMq)->req(
                'user[email=*]?user_password_hash=*',
                'iss',
                [$user_email, $user_password_hash]
            );
            return $user_id;
        }
        // Else Add new user and retrieve new user's id
        return (new \AlxMq)->req(
            'user[user_name=*,email=*,user_password_hash=*,user_registration_ip=*]>',
            'sssss',
            [$user_name, $user_email, $user_password_hash, $_SERVER['REMOTE_ADDR']]
        );
    }

    function init_activation($user_email)
    {
        $user_activation_hash = sha1(uniqid(mt_rand(), true)); // generate random hash for email verification (40 char string)
        (new \AlxMq)->req(
            'user[email=*]?user_activation_hash=*',
            'iss',
            [$user_email, $user_activation_hash]
        );
        return $user_activation_hash;
    }

    /**
     *
     * @param $user_password_new
     *
     * @return bool
     */
    function set_password($user_password_new)
    {
        //
        // crypt the new user's password with the PHP 5.5's password_hash() function
        $user_password_hash = \User\Common\get_hash_of_password($user_password_new);
        //
        // write users new hash into database
        return \User\Common\Model\set_param($user_password_hash, 'user_password_hash');
    }

    /**
     * @param $paramValue
     * @param $paramNameUntrusted
     *
     * @return bool
     */
    function set_param($paramValue, $paramNameUntrusted)
    {
        $memo = Single::getInstance();
        $paramName = preg_replace('![^a-z0-9_-]!i', '', $paramNameUntrusted);
        $isSuccess = (new \AlxMq)->req("user[id=*]?{$paramName}=*", 'is', [(int)$_SESSION['user_id'], (string)$paramValue]);
        //
        if ($isSuccess) {
            $_SESSION[$paramName] = $paramValue;
            $memo->add_message('%MESSAGE_USER_PARAM_CHANGED_SUCCESSFULLY%');
            return true;
        }
        else {
            $memo->add_error('%MESSAGE_USER_PARAM_CHANGE_FAILED%');
        }
        return false;
    }

    /**
     * Update or create session ('rememberme') token hash
     *
     * @param $current_rememberme_token
     * @param $random_token_string
     */
    function update_session_token($current_rememberme_token, $random_token_string)
    {
        $paramsString = 'user_rememberme_token=*, user_login_agent=*, user_login_ip=*, user_login_datetime=*, user_last_visit=*';
        $sigma        = 'sssss';
        $values       = [$random_token_string, $_SERVER['HTTP_USER_AGENT'], $_SERVER['REMOTE_ADDR']];
        //
        // record the new token for this user/device
        if ($current_rememberme_token == '') {
            (new \AlxMq())->req(
                "user_connections[user_id=*,{$paramsString}]>",
                "i{$sigma}",
                array_merge([(int)$_SESSION['user_id']], $values)
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
    }

    function is_user_session_valid($user_id, $token)
    {
        return !!(new \AlxMq())->req(
            'user[id=* && user_connections.user_rememberme_token=*]?count',
            'is', [(int)$user_id, (string)$token]
        );
    }

}
