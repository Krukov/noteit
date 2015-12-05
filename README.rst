======================================
noteit - making and getting notes ewerywhere  beta
======================================

.. image:: https://travis-ci.org/Krukov/noteit-backend.svg?branch=master
    :target: https://travis-ci.org/Krukov/noteit-backend
.. image:: https://img.shields.io/coveralls/Krukov/noteit-backend.svg
    :target: https://coveralls.io/r/Krukov/noteit-backend

--------------------------------
The tool for simple store some notes
--------------------------------

That tool I created for my own purposes, but I will glad if you will use it too.

I love commandline tools like `howdoi <https://github.com/gleitz/howdoi>`_ or `fuckit <https://github.com/ajalt/fuckitpy>`_, they are really awesome.
Sometimes we want to note something simple, some usefull: command like *tar zxvf* or password from some service(it is bad idea), and that it will be great, if you can make this note simple and fast, and than get this note anywhere. So, take this tool and enjoy!


How to
=================

Install
-----------------


Thare are 3 ways to use this tool:

* simple/true/pythonic way:

::

	pip install noteit

* manual install way (for those who do not use pip)

::

	$ wget https://raw.githubusercontent.com/Krukov/noteit/stable/noteit/noteit -O /usr/bin/noteit --no-check-certificate
	$ chmod +x /usr/bin/noteit



* curl way (for those who do not want install)

::

	$ python -c "$(curl -s https://raw.githubusercontent.com/Krukov/noteit/stable/noteit/noteit)" [ARGUMENTS]


* hardcore curl way (for those who do not use python :fire:)

Soon


Using
------------

::

	$ /# noteit 
	>Input username: krukov
	>Input your password: 
	>If you are not registered yet, answer the question 'Do you like this tool?': yes
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



*FUTURE*
==========
 - json base api
 - drop note
 - aliases for notes
 - save files
 - browse notes as html
