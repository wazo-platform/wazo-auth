.PHONY: test-setup test test-image test-prerequisit

test-setup: test-prerequisit test-image ;

test-prerequisit:
	docker pull python:2.7
	docker pull n3llyb0y/wait
	docker pull rabbitmq
	docker pull progrium/consul
	docker build --no-cache -t xivo/xivo-auth ..
	docker build --no-cache -t xivo/xivo-auth-tests-data -f Dockerfile-data .

test-image:
	docker build --no-cache -t xivo/xivo-auth-tests -f Dockerfile-auth-test ..

test:
	nosetests
