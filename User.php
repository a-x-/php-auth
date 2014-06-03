<?php
/**
 * @file AB-STORE / test.php
 * Created: 28.05.14 / 23:06
 */
namespace User {
    require_once 'PHPLogin.php';
    require_once "$_SERVER[DOCUMENT_ROOT]/_ass/common.php";

    /**
     * @deprecated
     * @todo довести
     */
    function Logout()
    {
        global $login;
        $login->deleteRememberMeCookie();
        //
        $_SESSION = array();
        session_destroy();
        //
        $login->messages[] = MESSAGE_LOGGED_OUT;
    }


} // User

namespace User\Signup {
    /**
     * 1.
     * handles the entire registration process. checks all error possibilities, and creates a new user in the database if
     * everything is fine
     * @param $user_name
     * @param $user_email
     * @param $additionFields
     * @param $extraFields
     * @param $linkFields
     * @internal param $user_password
     * @internal param $user_password_repeat
     * @internal param $captcha
     */
    function checkPostData($user_name, $user_email, $additionFields, $extraFields, $linkFields)
    {
        global $login;
        if(!$login->isAllowCurrentUserRegistration()) return;
        // prevent database flooding
        $user_name = trim($user_name);
        $user_email = trim($user_email);
        $captcha = (isset($additionFields['captcha'])) ? trim($additionFields['captcha']) : '';
        $user_password_repeat = (isset($additionFields['user_password_repeat'])) ? trim($additionFields['user_password_repeat']) : '';
        $user_password_new = (isset($additionFields['user_password_new'])) ? trim($additionFields['user_password_new']) : '';
        //
        // check provided data validity
        if (!ALLOW_NO_CAPTCHA && strtolower($captcha) != strtolower($_SESSION['captcha'])) {
            $login->errors[] = MESSAGE_CAPTCHA_WRONG;
        } elseif (empty($user_name)) {
            $login->errors[] = MESSAGE_USERNAME_EMPTY;
        } elseif (!ALLOW_NO_PASSWORD && empty($user_password_new) || !ALLOW_NO_PASSWORD_RETYPE && empty($user_password_repeat)) {
            $login->errors[] = MESSAGE_PASSWORD_EMPTY;
        } elseif (!ALLOW_NO_PASSWORD_RETYPE && $user_password_new !== $user_password_repeat) {
            $login->errors[] = MESSAGE_PASSWORD_BAD_CONFIRM;
        } elseif (!ALLOW_NO_PASSWORD && strlen($user_password_new) < 6) {
            $login->errors[] = MESSAGE_PASSWORD_TOO_SHORT;
        } elseif (strlen($user_name) > 64 || strlen($user_name) < 2) {
            $login->errors[] = MESSAGE_USERNAME_BAD_LENGTH;
        } elseif (!preg_match($login->USER_NAME_VERIFICATION_REGEX, $user_name)) {
            $login->errors[] = MESSAGE_USERNAME_INVALID;
        } elseif (empty($user_email)) {
            $login->errors[] = MESSAGE_EMAIL_EMPTY;
        } elseif (strlen($user_email) > 254) {
            $login->errors[] = MESSAGE_EMAIL_TOO_LONG;
        } elseif (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
            $login->errors[] = MESSAGE_EMAIL_INVALID;
            //
            // finally if all the above checks are ok
        } else {
            $result_row = $login->getUserDataFromEmail($user_email);
            // if email already in the database
            if (isset($result_row->user_id)) {
                $login->errors[] = MESSAGE_EMAIL_ALREADY_EXISTS;
                //
                // Ok user can be create
            } else {
                if (ALLOW_NO_PASSWORD) {
                    $user_password_new = \Invntrm\generateStrongPassword();
                }
                // crypt the user's password with the PHP 5.5's password_hash() function.
                $user_password_hash = $login->getPasswordHash($user_password_new);
                // generate random hash for email verification (40 char string)
                $user_activation_hash = sha1(uniqid(mt_rand(), true));
                $query_new_user_insert = $login->writeNewUserDataIntoDB($user_name, $user_email, $user_password_hash, $user_activation_hash);
                $login->writeNewExtraUserDataIntoDB($user_email,$extraFields,$linkFields);
                if ($query_new_user_insert) {
                    // send a verification email
                    if (\User\Signup\sendVerifyMail($user_email, $user_activation_hash)) {
                        // when mail has been send successfully
                        $login->messages[] = MESSAGE_VERIFICATION_MAIL_SENT;
                    } else {
                        // delete this users account immediately, as we could not send a verification email
                        $login->deleteUser($user_email);
                        $login->errors[] = MESSAGE_VERIFICATION_MAIL_ERROR;
                    }
                } else {
                    $login->errors[] = MESSAGE_REGISTRATION_FAILED;
                }
            }
        }
        $messages = $login->errors+$login->messages;
        $messagesStr = join('|',$messages);
        header('Location: /profile/signup/sent/?messages=' . $messagesStr);
    }

    /*
     * 2.
     * sends an email to the provided email address
     * @return boolean gives back true if mail has been sent, gives back false if no mail could been sent
     */
    function sendVerifyMail($user_email, $user_activation_hash)
    {
        global $login;
        $mail = $login->getPHPMailerObject();
        //
        $mail->From = EMAIL_VERIFICATION_FROM;
        $mail->FromName = EMAIL_VERIFICATION_FROM_NAME;
        $mail->AddAddress($user_email);
        $mail->Subject = EMAIL_VERIFICATION_SUBJECT;
        //
        $link = "http://$_SERVER[HTTP_HOST]/profile/signup/verification/?"
            . http_build_query(['email' => $user_email, 'code' => $user_activation_hash]);
        //
        // the link to your register.php, please set this value in config/email_verification.php
        if (EMAIL_BODY_TYPE == 'html') {
            $link = "<a href='$link'>" . WORDING_LETTER_SUBMIT . "</a>";
        }
        $mail->Body = \Invntrm\specifyTemplate(EMAIL_VERIFICATION_CONTENT, ['link' => $link]);
        //
        if (!$mail->Send()) {
            $login->errors[] = MESSAGE_VERIFICATION_MAIL_NOT_SENT . $mail->ErrorInfo;
            return false;
        } else {
            return true;
        }
    }

    /**
     * 3.
     * checks the id/verification code combination and set the user's activation status to true (=1) in the database
     * @param $user_email
     * @param $user_activation_hash
     */
    function verifyMailCode($user_email, $user_activation_hash)
    {
        global $login;
        if (empty($user_activation_hash)) {
            $login->errors[] = MESSAGE_LINK_PARAMETER_EMPTY;
        }
        if (empty($user_email)) {
            $login->errors[] = MESSAGE_EMAIL_EMPTY;
        }
        // if database connection opened
        if ($login->databaseConnection()) {
            // try to update user with specified information
            $query_update_user = $login->writeUsersActiveStatusIntoDB($user_email, $user_activation_hash);
            //
            if ($query_update_user->rowCount() > 0) {
                if(ALLOW_AUTO_SIGNIN_AFTER_VERIFY){
                    $login->_writeUserDataIntoSession($login->getUserDataFromEmail($user_email));
                }
                header('Location: ' . '/profile/?message=%MESSAGE_REGISTRATION_ACTIVATION_SUCCESSFUL%');
            } else {
                // send bug report
                \Invntrm\bugReport2(
                    'PHPLogin::verifyMailCode', 'verification finish stage failed on the BD recording: '
                    . \Invntrm\varDumpRet($query_update_user)
                );
                // delete this users account immediately, as we could not send a verification email
                $login->deleteUser($user_email);
                header('Location: ' . '/profile/signup/?error=%MESSAGE_REGISTRATION_ACTIVATION_NOT_SUCCESSFUL%');
            }
        }
    }

}

/**
 * @todo довести
 * @deprecated
 */
namespace User\Reset {
/**
 * @deprecated
 * @todo довести
 * 1.
 * Sets a random token into the database (that will verify the user when he/she comes back via the link
 * in the email) and sends the according email.
 */
function checkPostData($user_email)
{
    global $login;
    $user_email = trim($user_email);
    //
    if (empty($user_email)) {
        $login->errors[] = MESSAGE_USERNAME_EMPTY;
    } else {
        // generate timestamp (to see when exactly the user (or an attacker) requested the password reset mail)
        // btw this is an integer ;)
        $temporary_timestamp = time();
        // generate random hash for email password reset verification (40 char string)
        $user_password_reset_hash = sha1(uniqid(mt_rand(), true));
        // database query, getting all the info of the selected user
        $result_row = $login->getUserDataFromEmail($user_email);
        //
        // if this user exists
        if (isset($result_row->user_id)) {
            //
            // store his password_reset_hash in the DB
            $query_update = $login->writeUsersPasswordResetTempHashIntoDB($user_password_reset_hash, $temporary_timestamp, $user_email);
            //
            // check if exactly one row was successfully changed:
            if ($query_update->rowCount() == 1) {
                // send a mail to the user, containing a link with that token hash string
                \User\Reset\sendVerifyMail($result_row->email, $user_password_reset_hash);
                return true;
            } else {
                $login->errors[] = MESSAGE_DATABASE_ERROR;
            }
        } else {
            $login->errors[] = MESSAGE_USER_DOES_NOT_EXIST;
        }
    }
    // return false (this method only returns true when the database entry has been set successfully)
    return false;
}


/**
 * 2.
 * Sends the password-reset-email.
 * @param $user_email
 * @param $user_password_reset_hash
 * @return bool
 */
function sendVerifyMail($user_email, $user_password_reset_hash)
{
    global $login;
    $mail = $login->getPHPMailerObject();
    $mail->From = EMAIL_PASSWORDRESET_FROM;
    $mail->FromName = EMAIL_PASSWORDRESET_FROM_NAME;
    $mail->AddAddress($user_email);
    $mail->Subject = EMAIL_PASSWORDRESET_SUBJECT;
    //
    $link = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'] . '?password_reset';
    $link .= '&user_email=' . urlencode($user_email) . '&verification_code=' . urlencode($user_password_reset_hash);
    if (EMAIL_BODY_TYPE == 'html') {
        $link = "<a href='$link'>" . WORDING_LETTER_SUBMIT . "</a>";
    }
    $mail->Body = \Invntrm\specifyTemplate(EMAIL_PASSWORDRESET_CONTENT, ['link' => $link]);
    //
    if (!$mail->Send()) {
        $login->errors[] = MESSAGE_PASSWORD_RESET_MAIL_FAILED . $mail->ErrorInfo;
        return false;
    } else {
        $login->messages[] = MESSAGE_PASSWORD_RESET_MAIL_SUCCESSFULLY_SENT;
        return true;
    }
}



/**
 * @deprecated
 * @todo довести
 * 3.
 * Checks if the verification string in the account verification mail is valid and matches to the user.
 * @param $user_email
 * @param $verification_code
 */
function verifyMailCode($user_email, $verification_code)
{
    global $login;
    $user_email = trim($user_email);
    if (empty($user_email) || empty($verification_code)) {
        $login->errors[] = MESSAGE_LINK_PARAMETER_EMPTY;
    } else {
        // database query, getting all the info of the selected user
        $result_row = $login->getUserDataFromEmail($user_email);
        //
        // if this user exists and have the same hash in database
        if (isset($result_row->user_id) && $result_row->user_password_reset_hash == $verification_code) {
            $timestamp_one_hour_ago = time() - 3600; // 3600 seconds are 1 hour
            //
            if ($result_row->user_password_reset_timestamp > $timestamp_one_hour_ago) {
                // set the marker to true, making it possible to show the password reset edit form view
                $login->password_reset_link_is_valid = true;
            } else {
                $login->errors[] = MESSAGE_RESET_LINK_HAS_EXPIRED;
            }
        } else {
            $login->errors[] = MESSAGE_USER_DOES_NOT_EXIST;
        }
    }
}


    /**
     * @deprecated
     * @todo довести
     * 4.
     * Checks and writes the new password.
     * @param $user_email
     * @param $user_password_reset_verify_code
     * @param $user_password_new
     * @param $user_password_repeat
     */
function writeNewPassword($user_email, $user_password_reset_verify_code, $user_password_new, $user_password_repeat)
{
    global $login;
    // TODO: timestamp!
    $user_email = trim($user_email);
    //
    if (empty($user_email) || empty($user_password_reset_verify_code) || empty($user_password_new) || empty($user_password_repeat)) {
        $login->errors[] = MESSAGE_PASSWORD_EMPTY;
        // is the repeat password identical to password
    } else if ($user_password_new !== $user_password_repeat) {
        $login->errors[] = MESSAGE_PASSWORD_BAD_CONFIRM;
        // password need to have a minimum length of 6 characters
    } else if (strlen($user_password_new) < 6) {
        $login->errors[] = MESSAGE_PASSWORD_TOO_SHORT;
        // if database connection opened
    } else if ($login->databaseConnection()) {
        // crypt the user's password with the PHP 5.5's password_hash() function.
        $user_password_hash = $login->getPasswordHash($user_password_new);
        $query_update = $login->writeUsersNewHashIntoDB($user_password_hash, $user_password_reset_verify_code, $user_email);
        //
        // check if exactly one row was successfully changed:
        if ($query_update->rowCount() == 1) {
            $login->password_reset_was_successful = true;
            $login->messages[] = MESSAGE_PASSWORD_CHANGED_SUCCESSFULLY;
        } else {
            $login->errors[] = MESSAGE_PASSWORD_CHANGE_FAILED;
        }
    }
}

}

namespace User\Edit {
    /**
     * @deprecated
     * @todo довести
     * Edit the user's name, provided in the editing form
     * @param $user_name
     */
    function name($user_name)
    {
        global $login;
        // prevent database flooding
        $user_name = substr(trim($user_name), 0, 64);
        //
        if (!empty($user_name) && $user_name == $_SESSION['user_name']) {
            $login->errors[] = MESSAGE_USERNAME_SAME_LIKE_OLD_ONE;
            // username cannot be empty and must be <...> and 2-64 characters
        } elseif (empty($user_name) || !preg_match($login->USER_NAME_VERIFICATION_REGEX, $user_name)) {
            $login->errors[] = MESSAGE_USERNAME_INVALID;
        } else {
            // write user's new data into database
            $login->writeUserParamIntoDB($user_name, 'user_name');
        }
    }


    /**
     * @deprecated
     * @todo довести
     * Edit the user's email, provided in the editing form
     */
    function email($user_email)
    {
        global $login;
        // prevent database flooding
        $user_email = substr(trim($user_email), 0, 254);
        //
        if (!empty($user_email) && $user_email == $_SESSION["user_email"]) {
            $login->errors[] = MESSAGE_EMAIL_SAME_LIKE_OLD_ONE;
            // user mail cannot be empty and must be in email format
        } elseif (empty($user_email) || !filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
            $login->errors[] = MESSAGE_EMAIL_INVALID;
        } else {
            // check if new email already exists
            $result_row = $login->getUserDataFromEmail($user_email);
            // if this email exists
            if (isset($result_row->user_id)) {
                $login->errors[] = MESSAGE_EMAIL_ALREADY_EXISTS;
            } else {
                //
                // write users new data into database
                $login->writeUserParamIntoDB($user_email, 'user_email');
            }
        }
    }

    /**
     * @deprecated
     * @todo довести
     * Edit the user's password, provided in the editing form
     */
    function password($user_password)
    {
        global $login;
        $user_password_old = $user_password['old'];
        $user_password_new = $user_password['new'];
        $user_password_repeat = $user_password['repeat'];
        if (empty($user_password_new) || empty($user_password_repeat) || empty($user_password_old)) {
            $login->errors[] = MESSAGE_PASSWORD_EMPTY;
            // is the repeat password identical to password
        } elseif ($user_password_new !== $user_password_repeat) {
            $login->errors[] = MESSAGE_PASSWORD_BAD_CONFIRM;
            // password need to have a minimum length of 6 characters
        } elseif (strlen($user_password_new) < 6) {
            $login->errors[] = MESSAGE_PASSWORD_TOO_SHORT;
            // all the above tests are ok
        } else {
            // database query, getting hash of currently logged in user (to check with just provided password)
            $result_row = $login->getUserDataFromEmail($_SESSION['user_email']);
            // if this user exists
            if (!isset($result_row->user_password_hash)) {
                $login->errors[] = MESSAGE_USER_DOES_NOT_EXIST;
            } // using PHP 5.5's password_verify() function to check if the provided passwords fits to the hash of that user's password
            elseif (!password_verify($user_password_old, $result_row->user_password_hash)) {
                $login->errors[] = MESSAGE_OLD_PASSWORD_WRONG;
            } else {
                $login->writeNewPasswordIntoDB($user_password_new);
            }

        }
    }

}



namespace User\Process {

    /**
     *  SIGN UP
     * check the possible REGISTER actions:
     * 1.  register new user
     * 2.  verification new user
     * @param $login \PHPLogin
     * @return bool
     */
    function signup($login)
    {
        //
        // 1.
        // if we have such a POST request, call the checkPostData() method
        if (
            $login->REQUEST_PATH_API == '/' && $login->REQUEST_METHOD == 'post'
        ) {
            \User\Signup\checkPostData($_POST['user_name'], $_POST['user_email'], @$_POST["opt"], @$_POST['extra'], @$_POST['link']);
        }
        else return false;
        return true;
    }

    /**
     * @param $login \PHPLogin
     * @return bool
     */
    function verify($login)
    {
        //
        // 2.
        // if we have such a GET request, call the verifyMailCode() method
        if (
            $login->REQUEST_PATH_API == '/' && $login->REQUEST_METHOD == 'put'
            && isset($_REQUEST['verified'])
        ) {
            \User\Signup\verifyMailCode(@$_REQUEST["email"], @$_REQUEST["code"]);
        } else return false;
        return true;
    }

    /**
     * SIGN IN
     * check the possible LOGIN actions:
     * 3.  login via post data, which means simply logging in via the login form.
     *     After the user has submit his login/password successfully, his
     *     logged-in-status is written into his session data on the server.
     *     This is the typical behaviour of common login scripts.
     * @param $login \PHPLogin
     * @return bool
     */
    function signin($login)
    {
        //
        // 3.
        // if user just submitted a login form
        if (
            $login->REQUEST_PATH_API == '/signin' && $login->REQUEST_METHOD == 'post'
        ) {
            $login->loginWithPostData($_POST['user_email'], $_POST['user_password'], @$_POST['user_rememberme']);
        } else
            return false;
        return true;
    }

    /**
     * @deprecated
     * @todo довести (сделать работающим сброс пароля)
     */
    function reset()
    {
        global $login;
        //
        // 1.3.
        // checking if user requested a password reset mail
            if (
                $login->REQUEST_PATH_API == '/' && $login->REQUEST_METHOD == 'put'
                && isset($_REQUEST['password'])
            ) {
                \User\Reset\checkPostData(@$_REQUEST['user_email']);
            }
            elseif (isset($_REQUEST["user_email"]) && isset($_REQUEST["code"])) {
                \User\Reset\verifyMailCode($_REQUEST["user_email"], $_REQUEST["code"]);
            }
            elseif (isset($_POST["submit_new_password"])) {
                \User\Reset\writeNewPassword(
                    $_REQUEST['user_email'],
                    $_REQUEST['verification_code'],
                    $_REQUEST['user_password_new'],
                    $_REQUEST['user_password_repeat']
                );
            }
        return true;
    }

    /**
     * @deprecated
     * @todo довести
     * @return bool
     */
    function edit()
    {
        global $login;
        //
        // 1.1.
        // User want change his profile // checking for form submit from editing screen
        if (
            $login->REQUEST_PATH_API == '/' && $login->REQUEST_METHOD == 'put'
        ) {
            // function below uses $_SESSION['user_id'] et $_SESSION['user_email']
            if (!empty($_REQUEST['user_name']) ) \User\Edit\name($_POST['user_name']);
            if (!empty($_REQUEST['user_email']) ) \User\Edit\email($_POST['user_email']);
            if (!empty($_REQUEST['user_password']) ) \User\Edit\password($_POST['user_password']);
        }
        else return false;
        return true;
    }

    /**
     * @deprecated
     * @todo довести
     *
     * @return bool
     */
    function signout()
    {
        global $login;
        //
        // 1.2.
        // if user tried to log out
        if (
            $login->REQUEST_PATH_API == '/signin' && $login->REQUEST_METHOD == 'delete'
        ) {
            \User\Logout();
        }
        else return false;
        return true;
    }
}