.PHONY: test-setup test test-image test-prerequisite test-db

test-setup: test-prerequisite test-image egg-info test-db build-oauth2-sync

build-oauth2-sync:
	docker build --no-cache -t oauth2-synchronization-service -f assets/external_auth/oauth2_synchronization_service/Dockerfile assets/external_auth/oauth2_synchronization_service

test-db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazopbx/wazo-auth-db ..

test-prerequisite:
	docker pull n3llyb0y/wait
	docker pull wazopbx/postgres-test
	docker pull swaggerapi/swagger-validator
	docker pull rabbitmq
	docker pull munkyboy/fakesmtp

test-image:
	docker build --no-cache -t wazopbx/wazo-auth ..
	docker build --no-cache -t wazopbx/wazo-auth-tests -f Dockerfile-auth-test ..

egg-info:
	cd .. && python setup.py egg_info

test:
	nosetests

mount:
	for f in $$(ls assets/*/docker-compose.yml); do echo "updating $$f" && sed -i 's/# - "$${LOCAL_GIT_REPOS}/- "$${LOCAL_GIT_REPOS}/' $$f; done

umount:
	for f in $$(ls assets/*/docker-compose.yml); do echo "updating $$f" && sed -i 's/- "$${LOCAL_GIT_REPOS}/# - "$${LOCAL_GIT_REPOS}/' $$f; done
