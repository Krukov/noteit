======================================
noteit - create and get notes anywhere 
======================================
.. image:: https://img.shields.io/badge/version-beta-yellow.svg
.. image:: https://travis-ci.org/Krukov/noteit-backend.svg?branch=master
    :target: https://travis-ci.org/Krukov/noteit-backend
.. image:: https://img.shields.io/coveralls/Krukov/noteit-backend.svg
    :target: https://coveralls.io/r/Krukov/noteit-backend

--------------------------------
The tool for simple store notes
--------------------------------

I created this tool for my own purposes, but I will be glad if you'll use it too.

I love commandline tools like `howdoi <https://github.com/gleitz/howdoi>`_ , they are really awesome.
Sometimes it is nesessary to note something simple and usefull: commands like *tar zxvf* or any password (it is bad idea). That will be great, if you could make a note simple and fast, and then get it anywhere. I hope, you will enjoy my tool!


How to
=================

Install
-----------------


There are 2 ways to install this tool:

* simple/true/pythonic way:

::

	pip install noteit

* manual install way (for those who do not use pip)

::

	$ wget https://raw.githubusercontent.com/Krukov/noteit/stable/noteit/noteit -O /usr/bin/noteit --no-check-certificate
	$ chmod +x /usr/bin/noteit

or just

::

	$ curl --silent --show-error --retry 5 {noteit_host}/install.sh | sudo sh

Using
------------

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
	>1: Noteit can get note from pipe
	>2: My first note
	$ /# noteit echo "You can run it"
	>Note saved
	$ /# noteit -l | sh
	You can run it
	$ /# noteit Create note with alias -a alias
	>Note saved
	$ /# noteit -a alias
	Create note with alias
	
	


*FUTURE*
==========
 - save files
 - encript notes
