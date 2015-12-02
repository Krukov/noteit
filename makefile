DIR?=noteit


release: clean
	rm -rf $(DIR)
	mkdir $(DIR)
	pyminifier --gzip client/__init__.py > $(DIR)/noteit
	cp $(DIR)/noteit $(DIR)/__init__.py
	git tag $(shell python client/__init__.py --version| grep "\d+.\d+.\d+" -Po)
	git push --tags
	python setup.py register -r pypitest
	python setup.py sdist upload -r pypitest

clean:
	find . -name *.pyc -delete
	rm -rf $(shell find . -name __pycache__) build *.egg-info dist
