# PHP-Auth
Status: **Pre-Alpha**

This lib based on [reborn](https://github.com/panique/php-login-advanced/issues/23) fork [devplanete/php-login-advanced](https://github.com/devplanete/php-login-advanced),
of the project [panique/PHP-Login-Advanced](https://github.com/panique/php-login-advanced) which is not maintained anymore.

# Dependency

* [a-x-/backend](//github.com/a-x-/backend) — my own exotic mysqli wrapper lib and common methods.

## Dependecy Injection (DI)

* Send mail module.

# Code review
## Start from
[UserInterface.php](https://github.com/a-x-/php-auth/blob/big-php-login-refactoring/UserInterface.php).

Front open functions.

## Model
[UserModel.php](https://github.com/a-x-/php-auth/blob/big-php-login-refactoring/UserModel.php).

DB wrapper with specific methods.

## Common
Common (convention-private) functions: [UserCommon.php](https://github.com/a-x-/php-auth/blob/big-php-login-refactoring/UserCommon.php)

Contains setting holder singleton (class Single).

## Include point
[User.php](https://github.com/a-x-/php-auth/blob/big-php-login-refactoring/User.php).

User singleton class.

Takes settings and checks php version (load polyfill, is need).


# TODO

* Fix and swith on password and mail edit and reset.
* Cover by tests.
* Add translation module as DI.
* Move out data filters and add this as DI module.
* Fix composer autoloading
* Clean up code.
* Destroy singleton settings storage.
* Implement exceptions.
* Add two mode: 1) set cookie and 2) return json only.
    - 1th useful for simple systems.
    - 2th can be using as [SSO](http://en.wikipedia.org/wiki/Single_sign-on) system base.
* Add into github existing API declaration and wrapper implementation.
* Write human readable docs and readme.

# License

Licensed under [MIT](http://www.opensource.org/licenses/mit-license.php).
You can use this lib for free for any
private or commercial projects.