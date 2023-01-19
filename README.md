<p align="center"><img src="https://github.com/wazo-platform/wazo-platform.org/raw/master/static/images/logo.png" height="200"></p>

# wazo-auth

[![Build Status](https://jenkins.wazo.community/buildStatus/icon?job=wazo-auth)](https://jenkins.wazo.community/job/wazo-auth)
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth?ref=badge_shield)

An authentication micro-service able to create tokens, check ACLs, delete expired tokens and much more.

* Create and manage users
* Create and manage groups
* Create and manage policies
* Create and store tokens
* External authentication with LDAP, Google and Microsoft

## Usage

Launching wazo-auth

```sh
wazo-auth [--user <user>] --config-file <path/to/config/file>
```

Getting a token

```sh
curl -k -i -X POST -H 'Content-Type: application/json' -u "alice:alice" "http://localhost:9497/0.1/token" -d '{}'
```

Retrieving token data

```sh
curl -k -i -X GET -H 'Content-Type: application/json' "http://localhost:9497/0.1/token/${TOKEN}"
```

## Bootstrapping wazo-auth

In order to be able to create users, groups and policies you have to be authenticated. The bootstrap
process allows the administrator to create a first user with the necessary rights to be able to add
other users.

We create the initial credentials. The username and password can then be used
to create a token with the `#` acl. This can be done using the
`wazo-auth-bootstrap` command.

```sh
wazo-auth-bootstrap complete
```

This script will create a configuration file named `/root/.config/wazo-auth-cli/050-credentials.yml`
containing all necessary information to be used from the `wazo-auth-cli`.

## Docker

The wazoplatform/wazo-auth image can be built using the following command:

```sh
docker build -t wazoplatform/wazo-auth .
```

The wazoplatform/wazo-auth-db image can be built using the following command:

```sh
docker build -f contribs/docker/Dockerfile-db -t wazoplatform/wazo-auth-db .
```

## Configuration

The default configuration file is located in `/etc/wazo-auth/config.yml`. As with all other Wazo
services, it can be overridden (and should only be overridden this way) with YAML files located in
`/etc/wazo-auth/conf.d/`.

### Enabling the users registration API

To enable the users registration (`/users/register`) API endpoint, add a file containing the following
lines to the `/etc/wazo-auth/conf.d` directory and restart wazo-auth

```yaml
enabled_http_plugins:
  user_registration: true
```

## Testing

### Running unit tests

```sh
apt-get install libldap2-dev libpq-dev python-dev libffi-dev libyaml-dev libsasl2-dev
pip install tox
tox --recreate -e py37
```

### Running integration tests

```sh
tox -e integration
```

### Load testing

It is possible to test wazo-auth with [ab](https://httpd.apache.org/docs/2.4/programs/ab.html).

#### Dependencies

* ab

```sh
apt-get update && apt-get install apache2-utils
```

#### Running the tests

With the following content in `/tmp/body.json`

```json
{}
```

```sh
ab -n1000 -c25 -A 'alice:alice' -p /tmp/body.json -T 'application/json' "http://localhost:9497/0.1/token"
```

This line will start 25 process creating 1000 tokens with the username and password alice alice

## How to get help

If you ever need help from the Wazo Platform community, the following resources are available:

* [Discourse](https://wazo-platform.discourse.group/)
* [Mattermost](https://mm.wazo.community)

## Contributing

You can learn more on how to contribute in the [Wazo Platform documentation](https://wazo-platform.org/contribute/code).

## License

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fwazo-platform%2Fwazo-auth?ref=badge_large)
