====================================================================
:ledger: noteit v2 - note taking with CLI (use GitHub Gist as store)
====================================================================

Make Notes with CLI (zero dependence)
-------------------------------------

I created this tool for my own purposes, but I will be glad if you'll use it too.

I love commandline tools like `howdoi <https://github.com/gleitz/howdoi>`_ , they are really awesome.
Sometimes it is necessary to note something simple and useful: commands like *tar zxvf* or any password. That would be great, if you could make a note simple and fast, and then get it anywhere. I hope, you will enjoy this tool!


Features
========

* \:octocat: Store data in your gists, so you need GitHub account. By default all notes stored at private gist.
* \:earth_americas: Share your notes with others.
* \:books: Use notebooks to organize your notes.
* \:closed_lock_with_key: Secure. You can encrypt your notes by your own key.
* \:package: Minimal dependence and size (about 7 kb), all you need is python.
* \:snake: Support python 2.6, 2.7, 3.4 and upper (for 2.6 you need to install argparse package).
* \:rocket: Easy to install (curl --silent --show-error --retry 5 http://krukov.pythonanywhere.com//install.sh | sudo sh).
* \:beginner: Easy to use.
* >_ CLI - that's awesome. Work at all platforms (I hope).


How it works
-------------

pass

How to install
--------------

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

	$ curl --silent --show-error --retry 5 http://krukov.pythonanywhere.com/install.sh | sudo sh


How to use
----------

::

	$ /# noteit 
	>Input username: newUser
	>Input your password: ****
	        ALIAS               UPDATED        PUBLIC
   	        public           09-04-16 22:31      ✓   
                readme           10-04-16 23:39          
	$ /# noteit new note -a new
	Saved
	$ /# echo "Noteit can get note from pipe" | noteit -a print_pipe
	Saved
	$ /# noteit 
	        ALIAS               UPDATED        PUBLIC
   	        public           09-04-16 22:31      ✓   
        	readme           10-04-16 23:39          
      	      print_pipe         13-04-16 23:17          
      	$ /# noteit echo "You can run it" -a test
	Saved
	$ /# noteit -l | sh
	You can run it
	$ /# noteit Create note with alias and in notebook -a alias -n mynotebook
	Saved
	$ /# noteit --all
	   NOTEBOOK           ALIAS               UPDATED        PUBLIC
	   __main__           public           13-04-16 23:19      *   
	   __main__           readme           10-04-16 23:39          
   	   __main__         print_pipe         13-04-16 23:17          
	  mynotebook          alias            13-04-16 23:24
	$ /# noteit -a alias -n mynotebook
	Create note with alias and in notebook
	$ /# noteit Super secret note -a ss --key
	Input encryption key: *****
	Saved


*FUTURE*
========
 - colorize
 - search
