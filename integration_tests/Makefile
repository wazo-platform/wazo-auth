test-setup: test-image egg-info test-db build-oauth2-sync

build-oauth2-sync:
	docker build --no-cache -t oauth2-synchronization-service -f assets/external_auth/oauth2_synchronization_service/Dockerfile assets/external_auth/oauth2_synchronization_service

test-db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazopbx/wazo-auth-db ..

test-image:
	docker build --no-cache -t wazopbx/wazo-auth ..
	docker build --no-cache -t wazopbx/wazo-auth-tests -f Dockerfile-auth-test ..

egg-info:
	cd .. && python3 setup.py egg_info

test:
	pytest -x

.PHONY: test-setup test test-image test-db
