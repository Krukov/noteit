======================================
noteit - create and get notes anywhere 
======================================

Make Notes with CLI (zero dependence)
------------------------------------

I created this tool for my own purposes, but I will be glad if you'll use it too.

I love commandline tools like `howdoi <https://github.com/gleitz/howdoi>`_ , they are really awesome.
Sometimes it is necessary to note something simple and useful: commands like *tar zxvf* or any password. That will be great, if you could make a note simple and fast, and then get it anywhere. I hope, you will enjoy this tool!


Why
===

* :package: Minimal dependence and size (about 7 kb), all you need is python
* :snake: Support python 2.6, 2.7, 3.4 and upper (for 2.6 you need to install argparse package)
* :rocket: Easy to install (curl --silent --show-error --retry 5 http://krukov.pythonanywhere.com//install.sh | sudo sh)
* :beginner: Easy to use
* :closed_lock_with_key: Secure. Encrypt your notes by default (you can use your own key)
* >_ CLI - that's awesome. Work at all platforms (I hope)


.. image:: https://github.com/Krukov/noteit/raw/master/demo.gif


How
===

it works
--------

When you run noteit at first time he goes to the noteit-backend host with basic auth headers and automatically register
you at service. After he get token from server and save it locally at your home directory, generate and save double md5
hash of your credentials for continue use by key for using by encryption key. Than noteit using saved token for
authorization. All encrypted notes storing at noteit backend server, that's why you can get it anywhere you want.
All notes have alias, you can determine it by option '-a' or backend will generate random alias.


security
--------

When you use password passing from option or injected, using basic auth, that is why I recommend you use long password with 6 or more random symbols.
All notes encrypt by saved hash of you password (at backend stored another hash) or by key from '--key' option.
Manually you can disable encryption with option '--do-not-encrypt'.


to install
----------

There are 3 ways to install this tool:

* simple/true/pythonic way:

::

	pip install noteit

* manual install way (for those who do not use pip)

::

	$ wget https://raw.githubusercontent.com/Krukov/noteit/stable/noteit/noteit -O /usr/bin/noteit --no-check-certificate
	$ chmod +x /usr/bin/noteit

or just

::

	$ curl --silent --show-error --retry 5 http://krukov.pythonanywhere.com//install.sh | sudo sh


to use
------

::

	$ /# noteit 
	>Input username: krukov
	>Input your password: 
	>You haven't notes
	$ /# noteit My first note
	>Note saved
	$ /# echo "Noteit can get note from pipe" | noteit
	>Note saved
	$ /# noteit 
	>rsf: Noteit can get note from pipe
	>temme: My first note
	$ /# noteit echo "You can run it"
	>Note saved
	$ /# noteit -l | sh
	You can run it
	$ /# noteit Create note with alias -a alias
	>Note saved
	$ /# noteit
	>alias: Create note with alias
	>rsf: Noteit can get note from pipe
	>temme: My first note
	$ /# noteit -a alias
	Create note with alias



*FUTURE*
==========
 - simple caching
 - https!!! DONATE?
 - save files DONATE?
