.PHONY: test-image test-setup clean sync-context

test-setup:
	docker pull python:2.7
	docker pull n3llyb0y/wait
	docker pull rabbitmq
	docker pull progrium/consul
	docker build --no-cache -t xivo/xivo-auth ..
	docker build --no-cache -t xivo/xivo-auth-tests-data -f Dockerfile-data .
	docker build --no-cache -t xivo/xivo-auth-tests -f Dockerfile-auth-test ..

test:
	nosetests
