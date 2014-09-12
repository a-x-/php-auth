<?php
//require_once __DIR__ . '/vendor/a-x-/backend/Mq.php';
//require_once __DIR__ . '/vendor/a-x-/backend/common.php';
//require_once __DIR__ . '/vendor/phroute/phroute/src/Phroute/RouteCollector.php';
//require_once __DIR__ . '/vendor/phroute/phroute/src/Phroute/Dispatcher.php';
require_once __DIR__ . "/vendor/autoload.php";
require_once __DIR__ . "/UserCommon.php";
require_once __DIR__ . "/UserModel.php";
require_once __DIR__ . "/UserInterface.php";

/**
 * @license http://opensource.org/licenses/MIT MIT License
 */
class User
{
    public static function getInstance($settings = [])
    {
        static $instance = null;
        if (null === $instance) {
            $instance = new static($settings);
        }
        return $instance;
    }

    private function __clone() { }

    private function __wakeup() { }

    private $memo;

    protected function __construct($settings = [])
    {
        $this::php_password_polyfill();
        //
        // Rewrite default settings
        $this->memo           = $memo = \User\Common\Single::getInstance();
        $this->memo->settings = array_merge($this->memo->settings, $settings);
        //
        // Password-retype do not be true when allow-no-password is true
        if (!empty($memo->settings['ALLOW_NO_PASSWORD']) && !empty($memo->settings['ALLOW_NO_PASSWORD_RETYPE'])) {
            $memo->settings['ALLOW_NO_PASSWORD_RETYPE'] =
                $memo->settings['ALLOW_NO_PASSWORD_RETYPE'] || $memo->settings['ALLOW_NO_PASSWORD'];
        }
    }

    private static function php_password_polyfill()
    {
        // check for minimum PHP version
        if (version_compare(PHP_VERSION, '5.3.7', '<')) {
            throw new \Exception('Sorry, this script does not run on a PHP version smaller than 5.3.7 !');
        }
        else if (version_compare(PHP_VERSION, '5.5.0', '<')) {
            // if you are using PHP 5.3 or PHP 5.4 you have to include the password_api_compatibility_library.php
            // (this library adds the PHP 5.5 password hashing functions to older versions of PHP)
            require_once(__DIR__ . '/libraries/password_compatibility_library.php');
        }
    }
}
