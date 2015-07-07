# xivo-auth

[![Build Status](https://travis-ci.org/xivo-pbx/xivo-auth.svg)](https://travis-ci.org/xivo-pbx/xivo-auth)

A thin layer of business logic above consul to create tokens, create acl and delete expired tokens

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

# Using docker

    docker build -t xivo-auth .
    docker run -p 9497:9497 -v /conf/xivo-auth:/etc/xivo-auth/conf.d/ -it xivo-auth bash
    xivo-auth [-df] [-u <user>] [-c <path/to/config/file>]

Configuration
-------------

The default config is /etc/xivo-auth/config.yml, you could override in /etc/xivo-auth/conf.d/


Integration tests
-----------------

Executing integration tests require docker, the docker image is located in the
integration_tests directory.

Before starting build the xivo/xivo-auth image

```sh
make test-setup
```

To run the tests from the integration_tests directory

```sh
make test-image
nosetests
```

If you are using docker-machine you can change your ip address with the variable XIVO_AUTH_TEST_HOST.

```sh
export XIVO_AUTH_TEST_HOST=$(docker-machine ip <your-docker-machine>)
```
