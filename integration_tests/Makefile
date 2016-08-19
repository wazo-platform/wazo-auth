.PHONY: test-setup test test-image test-prerequisite

test-setup: test-prerequisite test-image egg-info

test-prerequisite:
	docker pull n3llyb0y/wait
	docker pull rabbitmq
	docker pull progrium/consul
	docker pull xivo/postgres-test
	docker pull swaggerapi/swagger-validator
	docker build --no-cache -t xivo/xivo-auth-tests-data -f Dockerfile-data .

test-image:
	docker build --no-cache -t xivo/xivo-auth ..
	docker build --no-cache -t xivo/xivo-auth-tests -f Dockerfile-auth-test ..

egg-info:
	cd .. && python setup.py egg_info

test:
	nosetests
