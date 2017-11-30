.PHONY: test-setup test test-image test-prerequisite test-db

test-setup: test-prerequisite test-image egg-info test-db

test-db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazopbx/wazo-auth-db ..

test-prerequisite:
	docker pull n3llyb0y/wait
	docker pull wazopbx/wazo-base-db
	docker pull swaggerapi/swagger-validator

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
