# xivo-auth

[![Build Status](https://travis-ci.org/xivo-pbx/xivo-auth.svg)](https://travis-ci.org/xivo-pbx/xivo-auth)

A thin layer of business logic above consul to create tokens, create acl and delete expired tokens

# Usage

Launching xivo-auth

    xivo_auth [--user <user>] --config <path/to/config/file>

Getting a token

```sh
curl -i -X POST -H 'Content-Type: application/json' -u "alice:alice" "localhost:9497/0.1/token" -d '{"type": "xivo_user"}'
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
docker build -t xivo/xivo-auth .
```

To run the tests from the integration_tests directory

```sh
docker build -t xivo/xivo-auth-tests -f Dockerfile .. && nosetests
```
