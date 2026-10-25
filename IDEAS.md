# IDEAS

Collection of ideas that still need to be played through.

## Config: `control` instead of `cps`, no `single` flag

Currently:

```yaml
name: mycluster
single: true
cps:
  provider: hetzner
  serverType: cx32
```

Problem: `single: true` is redundant and `cps` is cryptic.

Idea: `control` as the key. If properties sit directly inside = single node. If a list sits inside = multi control plane.

```yaml
# Single Node (properties directly)
name: mycluster
control:
  provider: hetzner
  serverType: cx32

# Multi Control Plane (list)
name: mycluster
control:
  - provider: hetzner
    serverType: cx32
    host: 10.0.0.1
  - provider: hetzner
    serverType: cx32
    host: 10.0.0.2
  - provider: hetzner
    serverType: cx32
    host: 10.0.0.3
```

Single only means: one control plane instead of 3. Workers are independent of that.

Detection: hash = single CP, array = multi CP. (`ref $control eq 'ARRAY'`)

```yaml
# Single CP + workers (normal production case)
name: mycluster
control:
  provider: hetzner
  serverType: cx32
workers:
  - name: pool1
    provider: hetzner
    nodes: 5

# Multi CP (HA)
name: mycluster
control:
  - provider: hetzner
    serverType: cx32
  - provider: hetzner
    serverType: cx32
  - provider: hetzner
    serverType: cx32
```

Open questions:

- Do we need a `nodes: 3` shortcut for "3 identical CPs"?
  ```yaml
  control:
    provider: hetzner
    serverType: cx32
    nodes: 3   # -> police1, police2, police3
  ```
  But then it is a hash with a `nodes` key, not a list — conflict with the hash=single detection.
  Possible solution: `nodes: 1` or no `nodes` = single, `nodes: 3` = multi.
  Then the list variant is only for heterogeneous CPs (different providers/types).
- Keep supporting `controlPlanes` / `cps` as an alias, or switch hard to `control`?
