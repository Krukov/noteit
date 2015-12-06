DIR?=noteit


mini: clean
	rm -rf $(DIR)
	mkdir $(DIR)
	pyminifier --gzip client/__init__.py > $(DIR)/noteit
	cp $(DIR)/noteit $(DIR)/__init__.py

tag:
	git tag $(shell python client/__init__.py --version| grep "\d+.\d+.\d+" -Po)
	git push origin stable --tags

pypi_pull:
	python setup.py register
	python setup.py sdist upload

commit:
	git commit -am "Release auto commit. ver. $(shell python client/__init__.py --version| grep "\d+.\d+.\d+" -Po)"

gch_stable:
	git checkout stable

clean:
	find . -name *.pyc -delete
	rm -rf $(shell find . -name __pycache__) build *.egg-info dist

release: gch_stable mini commit tag pypi_pull
