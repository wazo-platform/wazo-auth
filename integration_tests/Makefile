test-setup: test-image egg-info db build-oauth2-sync

build-oauth2-sync:
	docker build --no-cache -t oauth2-synchronization-service -f assets/external_auth/oauth2_synchronization_service/Dockerfile assets/external_auth/oauth2_synchronization_service

db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazoplatform/wazo-auth-db:local ..

test-image:
	docker build --no-cache -t wazoplatform/wazo-auth ..
	docker build --no-cache -t wazoplatform/wazo-auth-tests -f Dockerfile-auth-test ..

egg-info:
	cd .. && python3 setup.py egg_info

test:
	pytest

.PHONY: test-setup test test-image db
