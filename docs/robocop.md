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

## What it knows about the cluster

robocop never reads `ocp.yaml`. The two cluster-wide settings it cannot do
without travel in its Deployment, as plain environment variables that
`ocp apply` and `ocp deploy-robocop` write from `ocp.yaml` on every run:

| Variable           | From                   | Used for                                          |
|--------------------|------------------------|---------------------------------------------------|
| `OCP_DISTRIBUTION` | `kubernetes.dist`      | which agent it installs (`rke2` or `k3s`)         |
| `OCP_POD_CIDR`     | `network.pod_cidr`     | the `cluster-cidr` a joining control plane repeats |

Neither has a default. A robocop that finds one missing or unknown exits with
the reason on STDERR — the pod goes into `CrashLoopBackOff` — rather than
join nodes with a guessed distribution or pod network. The shipped
`share/robocop/deployment.yaml` carries neither, so a Deployment applied any
other way than through `ocp` fails the same way. The fix is always to roll
the Deployment out again with `ocp apply` or `ocp deploy-robocop`. Changing
either setting in `ocp.yaml` changes the pod template, so the next apply
restarts robocop with the new value.

The startup line in the pod log names both:

```
robocop 0.001 starting: security_level=secret namespace=ocp-system distribution=k3s pod_cidr=10.42.0.0/16
```

## Rolling out a new image

```bash
ocp deploy-image --tag v1.2.3
```

Replaces robocop's container image without a full `ocp apply`. It changes
only the image: a Deployment written by an OCP that did not yet set
`OCP_DISTRIBUTION` and `OCP_POD_CIDR` makes the new image exit at startup
until `ocp apply` or `ocp deploy-robocop` rewrites it.

## See also

- [Security model](security.md) — where PIN1 and PIN2 fit
- [`ocp.yaml` reference](configuration.md)
- ADRs [0001](adr/0001-split-cli-from-in-cluster-controller.md),
  [0002](adr/0002-nodes-and-providers-as-crds.md),
  [0021](adr/0021-robocop-polls-instead-of-watching.md)
