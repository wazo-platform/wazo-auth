# xivo-auth

xivo identity service

# Usage

Launching xivo-auth

```sh
python xivo_auth/bin/daemon.py [--user <user>] --config <path/to/config/file>
```

Getting a token

```sh
curl -i -X POST -H 'Content-Type: application/json' -d '{"login": "alice", "passwd": "alice"}' localhost:8080/0.1/tokens
```
