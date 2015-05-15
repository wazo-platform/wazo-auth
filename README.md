# xivo-auth

A thin layer of business logic above consul to create tokens, create acl and delete expired tokens

# Usage

Launching xivo-auth

    xivo_auth [--user <user>] --config <path/to/config/file>

Getting a token

    curl -i -X POST -H 'Content-Type: application/json' -u "alice:alice" localhost:6000/0.1/auth/tokens

# Using docker

Consul

    docker run -p 8400:8400 -p 8500:8500 -p 8600:53/udp -h node1 quintana/consul -server -bootstrap

XiVO auth

    docker build -t xivo-auth .
    docker run -p 6000:6000 -v /conf/xivo-auth:/etc/xivo-auth/conf.d/ -it xivo-auth bash
    xivo-auth [--user <user>] [--config <path/to/config/file>]
