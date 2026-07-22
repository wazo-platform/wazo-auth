# Scaling wazo-auth

wazo-auth splits its work into three roles, selectable per process with the
repeatable `--role` option or the `roles` configuration key:

- `api`: serve the REST API (and register in Consul when service discovery is
  enabled)
- `scheduler`: run periodic tasks (expired token and session cleanup)
- `init`: run one-shot startup tasks (schema upgrade gate, policy update,
  bootstrap user) then keep going with the other enabled roles — or exit if
  none is enabled

The default is all three roles in one process. Instances coordinate through
PostgreSQL advisory locks: startup one-shots and migrations are serialized
across instances, and the scheduler elects a single leader (another instance
takes over within one `token_cleanup_interval` if the leader dies). **Running
N identical replicas is therefore safe.**

## Topology 1: all-in-one (default)

Nothing to do. One `wazo-auth` process runs every role, as always.

## Topology 2: extra workers on the same host

Start additional API-only processes with the systemd template, using the
instance name as the port:

```sh
systemctl enable --now wazo-auth-worker@19497 wazo-auth-worker@29497
```

Workers are tied to the main unit (`PartOf=wazo-auth.service`): they stop and
restart with it. Each worker advertises its own port in Consul automatically
(`service_discovery.advertise_port` defaults to the real listening port).

nginx already routes the API through the `wazo-auth` upstream defined in
`/etc/nginx/conf.d/wazo-auth-upstream.conf`. To spread the traffic across
the workers, add one server line per worker and reload nginx:

```nginx
upstream wazo-auth {
    server 127.0.0.1:9497;    # main instance (all roles)
    server 127.0.0.1:19497;   # wazo-auth-worker@19497
    server 127.0.0.1:29497;   # wazo-auth-worker@29497
}
```

```sh
nginx -t && systemctl reload nginx
```

All instances share `/var/log/wazo-auth.log`. Per-instance streams are
available through journald (`journalctl -t wazo-auth-worker@19497`); pass
`--log-file` in a unit override if separate files are preferred.

## Topology 3: containers, N identical replicas

Because coordination happens in PostgreSQL, the simplest container topology
is N replicas of the same image and configuration — no role wiring, no port
juggling (each container listens on its own 9497):

```yaml
services:
  auth:
    image: wazoplatform/wazo-auth
    deploy:
      replicas: 3
    environment:
      XIVO_UUID: <stack uuid>
    # all replicas share the same postgres and rabbitmq
```

Front the replicas with any HTTP load balancer (or the orchestrator's
service VIP).

## Kubernetes sketch

Either of:

- one Deployment running the default role set with `replicas: N` — simplest,
  safe by design; or
- split roles: an `api` Deployment (`--role api`, N replicas) + a `scheduler`
  Deployment (`--role scheduler`, 1 replica) + `init` as a Job or
  initContainer (`wazo-auth --role init` runs the one-shots and exits 0).
