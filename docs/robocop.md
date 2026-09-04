# robocop — the in-cluster controller

`robocop` runs inside the cluster, in the `ocp-system` namespace, and
reconciles worker `OCPNode` custom resources: it provisions the machine,
installs Kubernetes on it, and joins it to the cluster. It is the half of OCP
that keeps working when your laptop is closed.

`ocp` (the CLI) bootstraps control planes. `robocop` manages workers. Neither
does the other's job.

## Turning it on

It is opt-in, via `ocp.yaml`:

```yaml
robocop: true
```

The default is `false`, but it flips to `true` automatically whenever any
control plane or worker pool uses the `hetzner` provider — because that is the
case where nodes appear and disappear without a human present.

`ocp apply` deploys it when it is enabled. You can also deploy or redeploy it
on its own:

```bash
ocp deploy-robocop
```

When robocop is *not* running, `ocp node add` falls back to driving the
reconciliation itself from the CLI. Same state machine, different driver.

## How credentials reach it

To join workers, robocop needs the cluster's join token and the private
automation (robo) SSH key. `robocop.security_level` decides how that material
gets to it:

```yaml
robocop:
  enabled: true
  security_level: secret   # secret (default) | secret_approved | inject
```

- **`secret`** (default) — `ocp deploy-robocop` decrypts the credentials with
  PIN1 and writes them into a `robocop-credentials` Kubernetes Secret. A pod
  restart self-heals from that Secret.
- **`secret_approved`** — same as `secret`, but writing the Secret
  additionally requires an explicit PIN2 approval prompt.
- **`inject`** — **not available yet.** The config accepts the value, but
  `ocp deploy-robocop` refuses to run with it:
  `robocop.security_level 'inject' is not yet available (k2)`. The intent is
  in-memory-only delivery with nothing ever persisted to a Secret; it is
  deferred until that work lands.

## Rolling out a new image

```bash
ocp deploy-image --tag v1.2.3
```

Replaces robocop's container image without a full `ocp apply`.

## See also

- [Security model](security.md) — where PIN1 and PIN2 fit
- [`ocp.yaml` reference](configuration.md)
- ADRs [0001](adr/0001-split-cli-from-in-cluster-controller.md),
  [0002](adr/0002-nodes-and-providers-as-crds.md),
  [0021](adr/0021-robocop-polls-instead-of-watching.md)
