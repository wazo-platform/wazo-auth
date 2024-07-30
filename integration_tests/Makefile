test-setup: test-image egg-info db saml-webapp build-oauth2-sync install-playwright

build-oauth2-sync:
	docker build --no-cache -t oauth2-synchronization-service -f assets/external_auth/oauth2_synchronization_service/Dockerfile assets/external_auth/oauth2_synchronization_service

db:
	docker build -f ../contribs/docker/Dockerfile-db -t wazoplatform/wazo-auth-db:local ..

saml-webapp:
	docker build --no-cache -f assets/saml/webapp/Dockerfile -t wazoplatform/wazo-saml-sso-webapp:local assets/saml/webapp

test-image:
	docker build --no-cache -t wazoplatform/wazo-auth ..
	docker build --no-cache -t wazoplatform/wazo-auth-tests -f Dockerfile-auth-test ..

install-playwright:
	playwright install

egg-info:
	cd .. && python3 setup.py egg_info

test:
	pytest --tracing off

.PHONY: test-setup test test-image db
