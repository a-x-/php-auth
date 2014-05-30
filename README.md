## A PHP login script (ADVANCED VERSION)
**In big restructurization process now. It's not ready for production**

This script is base on [panique/PHP-Login-Advanced](https://github.com/panique/php-login-advanced) who is not maintained anymore.
And based on [reborn](https://github.com/panique/php-login-advanced/issues/23) fork [devplanete/php-login-advanced](https://github.com/devplanete/php-login-advanced).

### A simple, but secure PHP login script with many features includes:

[panique](https://github.com/panique/php-login-advanced)
- users can register, login, logout (with username or email, password)
- captcha
- account verification via mail
- password reset
- edit user data (password, username, email)
- "remember me" / stay logged in cookies
- gravatars

[devplanete](https://github.com/devplanete/php-login-advanced)
- "remember me" supports parallel login from multiple devices
- i18n/internationalization: English, French, **Russian (new)** at the moment but it's easy to add a new language
- possibility to manage some user access levels
- a beautiful CSS style

[a-x-](https://github.com/a-x-/php-login-advanced)
- parametric signup
- switchable captcha, password retype, password fields on signup stage
- separated sample (not actual now)
- html and utf-8 mails (verify, reset) instead of plain and iso-8859-1
- moveable cnfig file
- ...

### IT stuffs...
- PDO used for database access
- mail sending via PHPMailer (**SMTP** or PHP's mail() function/linux sendmail)
- Uses the ultra-modern & future-proof PHP 5.5.BLOWFISH hashing/salting functions (includes the official PHP 5.3 & PHP 5.4 compatibility pack, which makes those functions available in those versions too)

## Screenshot

![Example screenshot](https://cloud.githubusercontent.com/assets/5228432/2852514/5cdb4126-d136-11e3-802e-c3ade2455cb5.png)

## Live-demo

No live demo page available at the moment

## Requirements

(in developing)

## Installation (quick setup)

(in developing)

## Troubleshooting & useful stuff

Please use a real SMTP provider for sending mail. Using something like gmail.com or even trying to send mails via
mail() will bring you into a lot of problems (unless you really really know what you are doing). Sending mails is a
huge topic. But if you still want to use Gmail: Gmail is very popular as an SMTP mail sending service and would
work for smaller projects, but sometimes gmail.com will not send mails anymore, usually because of:

1. "SMTP Connect error": PHPMailer says "smtp login failed", but login is correct: Gmail.com thinks you are a spammer. You'll need to
"unlock" your application for gmail.com by logging into your gmail account via your browser, go to http://www.google.com/accounts/DisplayUnlockCaptcha
and then, within the next 10minutes, send an email via your app. Gmail will then white-list your app server.
Have a look here for full explanaition: https://support.google.com/mail/answer/14257?p=client_login&rd=1

2. "SMTP data quota exceeded": gmail blocks you because you have sent more than 500 mails per day (?) or because your users have provided
 too much fake email addresses. The only way to get around this is renting professional SMTP mail sending, prices are okay, 10.000 mails for $5.

## How this script works

If you look into the code and at the file/folder-structure everything should be self-explaining.

## Useful links

- [How to use PDO](http://wiki.hashphp.org/PDO_Tutorial_for_MySQL_Developers)
- [Why you Should be using PHP's PDO for Database Access](http://net.tutsplus.com/tutorials/php/why-you-should-be-using-phps-pdo-for-database-access)
- [A little guideline on how to use the PHP 5.5 password hashing functions and its "library plugin" based PHP 5.3 & 5.4 implementation](http://www.dev-metal.com/use-php-5-5-password-hashing-functions/)
- [How to setup latest version of PHP 5.5 on Ubuntu 12.04 LTS](http://www.dev-metal.com/how-to-setup-latest-version-of-php-5-5-on-ubuntu-12-04-lts/). Same for Debian 7.0 / 7.1:
- [How to setup latest version of PHP 5.5 on Debian Wheezy 7.0/7.1 (and how to fix the GPG key error)](http://www.dev-metal.com/setup-latest-version-php-5-5-debian-wheezy-7-07-1-fix-gpg-key-error/)
- [Notes on password & hashing salting in upcoming PHP versions (PHP 5.5.x & 5.6 etc.)](https://github.com/panique/php-login/wiki/Notes-on-password-&-hashing-salting-in-upcoming-PHP-versions-%28PHP-5.5.x-&-5.6-etc.%29)
- [Some basic "benchmarks" of all PHP hash/salt algorithms](https://github.com/panique/php-login/wiki/Which-hashing-&-salting-algorithm-should-be-used-%3F)

## License

Licensed under [MIT](http://www.opensource.org/licenses/mit-license.php). You can use this script for free for any
private or commercial projects.

