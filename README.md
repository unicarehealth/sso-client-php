Single Sign On (SSO) Client for PHP
===================================

The PHP SSO Client portion of the Barebones SSO Server/Client.  Pairs with the SSO Server, which is an awesome, scalable, secure, flexible login system that's become a bit ridiculous - but it still rocks anyway.

Warning:  This GitHub project is the live development branch and is occasionally broken.  Do NOT use on production servers!  Use the official releases instead.

Features
--------

* Average memory footprint.  About 1MB RAM per connection.
* Classes and functions are carefully named to avoid naming conflicts with third-party software.
* When authentication is required prior to executing some task (e.g. posting a comment), the SSO client encrypts and sends the current request data ($_GET, $_POST, etc.) to the SSO server for later retrieval and will resume exactly where it left off in most cases (e.g. the comment is posted).
* Encrypts communications over the network (even HTTP).
* Communicates with the server on a schedule set by the client.  Allows for significantly reduced network overhead without affecting system integrity.
* And more.  See the official documentation for a more complete feature list.
* Also has a liberal open source license.  MIT or LGPL, your choice.
* Designed for relatively painless integration into your project.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

More Information
----------------

Documentation, examples, and official downloads of this project sit on the Barebones CMS website:

http://barebonescms.com/documentation/sso/

SSO Server on GitHub:

https://github.com/cubiclesoft/sso-server

Quick start video tutorials:

https://www.youtube.com/watch?v=Vbe4p-PUSTo&index=3&list=PLIvucSFZRDjgiSfsm707zn-bqKd64Eikb

How to use as a Composer Package
--------------------------------
1) Add the Unicare fork to the 'repositories' section of composer.json, e.g.:
```
"repositories": [
		{			
            "type": "vcs",
            "url": "https://github.com/unicarehealth/sso-client-php.git"
        }
    ]
```
2) Add the package to the 'require' section of composer.json, e.g.:
```
"require": {
	"cubiclesoft/sso-client-php": "dev-master"
}
```
3) Run 'composer update' from the command line to tell Composer to fetch required packages. You may also need to execute 'composer dump-autoload'.
```
>composer update
>composer dump-autoload
```

4) Now copy the folder /vendor/cubiclesoft/sso-client-php/sso-client to a public location in your web application (e.g. <application-root>/sso-client.

5) Complete the installation by opening the installer's web page in a browser (e.g. at <your-domain>/sso-client/install.php).

6) Once installation has completed and a config.php file has been created, delete file 'install.php' and the folders 'js' and 'css'.

7) In the bootstrap/initialisation code for you application add:
```
require_once('sso-client/config.php');
```
8) You can now use instances of SSOClient as required:
```
$ssoClient = new \Csa\Sso\Client\SSOClient();
```


