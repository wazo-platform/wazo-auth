# wazo-auth

[![Build Status](https://travis-ci.org/wazo-pbx/wazo-auth.svg)](https://travis-ci.org/wazo-pbx/wazo-auth)

A micro-service to create tokens, check ACLs and delete expired tokens

# Usage

Launching wazo-auth

    wazo_auth [--user <user>] --config <path/to/config/file>

Getting a token

```sh
curl -k -i -X POST -H 'Content-Type: application/json' -u "alice:alice" "https://localhost:9497/0.1/token" -d '{"backend": "xivo_user"}'
```

Retrieving token data

```sh
curl -k -i -X GET -H 'Content-Type: application/json' "https://localhost:9497/0.1/token/${TOKEN}"
```

# Docker

The wazopbx/wazo-auth image can be built using the following command:

    % docker build -t wazopbx/wazo-auth .

To run wazo-auth in docker, use the following commands:

    % docker run -p 9497:9497 -v /conf/wazo-auth:/etc/wazo-auth/conf.d/ -it wazopbx/wazo-auth bash
    % wazo-auth [-df] [-u <user>] [-c <path/to/config/file>]

The wazopbx/wazo-auth-db image can be built using the following command:

    % docker build -f contribs/docker/Dockerfile-db -t wazopbx/wazo-auth-db .


Configuration
-------------

The default config is /etc/wazo-auth/config.yml, you could override in /etc/wazo-auth/conf.d/

Enabling the users API
---------------------------

To enable the /users API add a file containing the following lines to the /etc/wazo-auth/conf.d directory and
restart wazo-auth

```
enabled_http_plugins:
    users: true
```

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


Load testing
------------

To test wazo-auth with ab

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

To add a new migration script for the database use the following command from the root of the project:

   % ./alembic_revision.sh "<description of the revision>"

To add a new ACL migration script use the following command from the root of the project:

   % ./alembic_revision.sh -a "<description of the revision>"

Available ACL policies are:

* `wazo_default_admin_policy`
* `wazo_default_user_policy`
