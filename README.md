# wazo-auth

[![Build Status](https://jenkins.wazo.community/buildStatus/icon?job=wazo-auth)](https://jenkins.wazo.community/job/wazo-auth)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth?ref=badge_shield)

A micro-service to create tokens, check ACLs and delete expired tokens

# Usage

Launching wazo-auth

    wazo_auth [--user <user>] --config <path/to/config/file>

Getting a token

```sh
curl -k -i -X POST -H 'Content-Type: application/json' -u "alice:alice" "http://localhost:9497/0.1/token" -d '{"backend": "wazo_user"}'
```

Retrieving token data

```sh
curl -k -i -X GET -H 'Content-Type: application/json' "http://localhost:9497/0.1/token/${TOKEN}"
```

## Boostraping wazo-auth

In order to be able to create users, groups and policies you have to be authenticated. The bootstrap
process allows the administrator to create a first user with the necessary rights to be able to add
other users.


### Bootstrapping wazo-auth

We create the initial credentials. The username and password can then be used
to create a token with the `auth.#` acl. This can be done using the
`wazo-auth-bootstrap` command.

```sh
wazo-auth-bootstrap complete
```

This script will create a configuration file named `/root/.config/wazo-auth-cli/050-credentials.yml`
containing all necessary information to be used from the `wazo-auth-cli`.


# Docker

The wazoplatform/wazo-auth image can be built using the following command:

    % docker build -t wazoplatform/wazo-auth .

To run wazo-auth in docker, use the following commands:

    % docker run -p 9497:9497 -v /conf/wazo-auth:/etc/wazo-auth/conf.d/ -it wazoplatform/wazo-auth bash
    % wazo-auth [-df] [-u <user>] [-c <path/to/config/file>]

The wazoplatform/wazo-auth-db image can be built using the following command:

    % docker build -f contribs/docker/Dockerfile-db -t wazoplatform/wazo-auth-db .


Configuration
-------------

The default config is /etc/wazo-auth/config.yml, you could override in /etc/wazo-auth/conf.d/

Enabling the users registration API
------------------------------------

To enable the users registration (/users/register) API endpoint, add a file containing the following lines to the /etc/wazo-auth/conf.d directory and
restart wazo-auth

```
enabled_http_plugins:
  user_registration: true
```

Running unit tests
------------------

```
apt-get install libldap2-dev libpq-dev python-dev libffi-dev libyaml-dev libsasl2-dev
pip install tox
tox --recreate -e py37
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
{"backend": "wazo_user"}
```

```sh
ab -n1000 -c25 -A 'alice:alice' -p /tmp/body.json -T 'application/json' "http://localhost:9497/0.1/token"
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


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth?ref=badge_large)
