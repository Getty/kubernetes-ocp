# IDEAS

Sammlung von Ideen die noch durchgespielt werden müssen.

## Config: `control` statt `cps`, kein `single` Flag

Aktuell:

```yaml
name: mycluster
single: true
cps:
  provider: hetzner
  serverType: cx32
```

Problem: `single: true` ist redundant und `cps` ist kryptisch.

Idee: `control` als Key. Wenn direkt Properties drin stehen = single node. Wenn eine Liste drin steht = multi control plane.

```yaml
# Single Node (Properties direkt)
name: mycluster
control:
  provider: hetzner
  serverType: cx32

# Multi Control Plane (Liste)
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

Single heißt nur: eine Control Plane statt 3. Workers sind unabhängig davon.

Erkennung: Hash = single CP, Array = multi CP. (`ref $control eq 'ARRAY'`)

```yaml
# Single CP + Workers (normaler Produktions-Case)
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

Offene Fragen:

- Braucht man einen `nodes: 3` Shortcut für "3 identische CPs"?
  ```yaml
  control:
    provider: hetzner
    serverType: cx32
    nodes: 3   # -> police1, police2, police3
  ```
  Aber dann ist es ein Hash mit `nodes` Key, nicht eine Liste — Konflikt mit der Hash=single Erkennung.
  Mögliche Lösung: `nodes: 1` oder kein `nodes` = single, `nodes: 3` = multi.
  Dann ist die Liste-Variante nur für heterogene CPs (verschiedene Provider/Typen).
- `controlPlanes` / `cps` als Alias weiter unterstützen oder hart auf `control` umstellen?
