.PHONY: test-setup test test-image test-prerequisite test-db

test-setup: test-prerequisite test-image egg-info test-db

test-db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazopbx/wazo-auth-db ..

test-prerequisite:
	docker pull n3llyb0y/wait
	docker pull wazopbx/wazo-base-db
	docker pull swaggerapi/swagger-validator
	docker build --no-cache -t wazopbx/wazo-auth-tests-data -f Dockerfile-data .

test-image:
	docker build --no-cache -t wazopbx/wazo-auth ..
	docker build --no-cache -t wazopbx/wazo-auth-tests -f Dockerfile-auth-test ..

egg-info:
	cd .. && python setup.py egg_info

test:
	nosetests
