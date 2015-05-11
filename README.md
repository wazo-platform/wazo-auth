# xivo-auth

A thin layer of business logic above consul to create tokens, create acl and delete expired tokens

# Usage

Launching xivo-auth

    python xivo_auth/bin/daemon.py [--user <user>] --config <path/to/config/file>

Getting a token

    curl -i -X POST -H 'Content-Type: application/json' -d '{"login": "alice", "passwd": "alice"}' localhost:8080/0.1/auth/tokens

# Using docker

Consul

    docker run -p 8400:8400 -p 8500:8500 -p 8600:53/udp -h node1 quintana/consul -server -bootstrap

XiVO auth

    docker build -t xivo-auth .
    docker run -p 8080:8080 -it xivo-auth bash
    $ xivo-auth [--user <user>] [--config <path/to/config/file>]
