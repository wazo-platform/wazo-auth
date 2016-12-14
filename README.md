# xivo-auth

[![Build Status](https://travis-ci.org/wazo-pbx/xivo-auth.svg)](https://travis-ci.org/wazo-pbx/xivo-auth)

A micro-service to create tokens, check ACLs and delete expired tokens

# Usage

Launching xivo-auth

    xivo_auth [--user <user>] --config <path/to/config/file>

Getting a token

```sh
curl -k -i -X POST -H 'Content-Type: application/json' -u "alice:alice" "https://localhost:9497/0.1/token" -d '{"backend": "xivo_user"}'
```

Retrieving token data

```sh
curl -k -i -X GET -H 'Content-Type: application/json' "https://localhost:9497/0.1/token/${TOKEN}"
```

# Docker

The wazopbx/xivo-auth image can be built using the following command:

    % docker build -t wazopbx/xivo-auth .

To run xivo-auth in docker, use the following commands:

    % docker run -p 9497:9497 -v /conf/xivo-auth:/etc/xivo-auth/conf.d/ -it wazopbx/xivo-auth bash
    % xivo-auth [-df] [-u <user>] [-c <path/to/config/file>]

The wazopbx/xivo-auth-db image can be built using the following command:

    % docker build -f contribs/docker/Dockerfile-db -t wazopbx/xivo-auth-db .


Configuration
-------------

The default config is /etc/xivo-auth/config.yml, you could override in /etc/xivo-auth/conf.d/


Running unit tests
------------------

```
apt-get install libldap2-dev libpq-dev python-dev libffi-dev libyaml-dev
pip install tox
tox --recreate -e py27
```


Running integration tests
-------------------------

You need Docker installed.

```
cd integration_tests
pip install -U -r test-requirements.txt
make test-setup
make test
```

If you are using docker-machine you must:
* change your ip address with the variable XIVO_AUTH_TEST_HOST.
* remove direct volume mount points

```sh
export XIVO_AUTH_TEST_HOST=$(docker-machine ip <your-docker-machine>)
sed -i '/delete-on-docker-machine/d' assets/*/docker-compose.yml
```


Load testing
------------

To test xivo-auth with ab

Dependencies

* ab

```sh
apt-get update && apt-get install apache2-utils
```

Running the tests

with the following content in '/tmp/body.json'

```javascript
{"backend": "xivo_user"}
```

```sh
ab -n1000 -c25 -A 'alice:alice' -p /tmp/body.json -T 'application/json' "https://localhost:9497/0.1/token"
```

This line will start 25 process creating 1000 tokens with the username and password alice alice


Adding a new database migration
-------------------------------

To add a new migration script for the database use the following command:

   % alembic -c alembic.ini revision -m "<description of the revision>"
