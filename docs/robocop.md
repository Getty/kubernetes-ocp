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

`ocp apply` deploys it when it is enabled — on every run, on a fresh cluster
and an existing one alike, whether or not `ocp.yaml` lists workers: its
credentials Secret first (left alone when already current, so a re-apply asks
for no PIN2), then its Deployment. It counts as part of the worker side:
`ocp apply --only workers` includes it, `--only control-planes` leaves it
alone, and `--dry-run` names a missing or outdated Secret and a missing
Deployment. Turning robocop off does not remove a robocop already running.
You can also deploy or redeploy it on its own:

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
- **`inject`** — the private robo key is never stored in the cluster.
  `ocp deploy-robocop` writes only the join URL, the token and the key's
  *public* half into the Secret; then you hand robocop the private key:

  ```bash
  ocp inject-key     # PIN1 if needed, then PIN2 as the admin approval
  ```

  It travels through a Kubernetes port-forward straight into the running
  pod's memory (robocop listens on `127.0.0.1:9999` inside the pod and only
  accepts the key whose public half it was deployed with). robocop's `/tmp`,
  where the key is handed to the installer, is a tmpfs.

  There is no checkpoint: **after a pod restart the key is gone** and you run
  `ocp inject-key` again. Until then robocop says so instead of pretending —
  the pod is not Ready, and every OCPNode that needs SSH (`Pending`,
  `Provisioning`, `Installing`) keeps its phase and carries the condition
  `SSHKeyAvailable=False` (reason `KeyInjectionRequired`). Nothing is
  provisioned without the key. `ocp apply` sees a not-Ready robocop and
  reconciles the workers from the CLI instead.

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
