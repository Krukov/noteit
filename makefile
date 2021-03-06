DIR?=noteit


mini: clean
	rm -rf $(DIR)
	mkdir $(DIR)
	pyminifier --gzip client/__init__.py > $(DIR)/noteit
	cp client/__init__.py $(DIR)/__init__.py

tag:
	git tag $(shell python3.4 client/__init__.py --version| grep "\d+.\d+.\d+" -Po)
	git push origin stable --tags

pypi_pull:
	python setup.py register
	python setup.py sdist upload

commit:
	git commit -am "Release auto commit. ver. $(shell python3.4 client/__init__.py --version| grep "\d+.\d+.\d+" -Po)"

merge:
	git merge master --no-edit

gch_stable:
	git checkout stable

clean:
	find . -name *.pyc -delete
	rm -rf $(shell find . -name __pycache__) build *.egg-info dist

release: gch_stable merge mini commit tag pypi_pull
	echo 'YO!'

encrypt%:
	@python -c "from client import _encrypt, get_version; print(_encrypt('$*'.strip(), get_version().replace('.', '_')))"
