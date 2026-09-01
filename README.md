# OCP - Omni Control Plane

OCP is a Perl CLI that deploys and manages Kubernetes clusters (RKE2 or K3s) on
Hetzner Cloud or your own servers. `ocp` is the command you run from your
laptop/CI: it bootstraps the control plane and reconciles the cluster.
`robocop` is a small controller that runs *inside* the cluster and manages
worker nodes via `OCPNode`/`OCPNodeProvider` custom resources.

This guide takes you from nothing to a running cluster and back, with
copy-paste commands. No prior Kubernetes/RKE2/Cilium knowledge assumed.

## Prerequisites

- **Docker.** OCP's toolchain is Docker-first: the Docker image is the
  supported way to run `ocp`, and it bundles every dependency (Perl, all CPAN
  modules, `kubectl` for manual debugging). Get Docker installed and move on.
- **One of:**
  - a **Hetzner Cloud API token** (Hetzner Cloud console -> your project ->
    Security -> API tokens) — OCP creates and destroys the servers for you, or
  - an **existing server you can SSH into as root** (bare metal, a VM, your
    own laptop) — OCP installs Kubernetes onto it but never creates or
    deletes the machine itself.
- A directory for your project (e.g. `mkdir mycluster && cd mycluster`) —
  everything OCP writes (`ocp.yaml`, encrypted keys, state) lives there.

OCP is **not published on CPAN** (this distribution builds with
`no_cpan = 1`) — `cpanm OCP` will not find it. Use the Docker image, or run
from a git checkout (see "Installing" below).

## Installing / running `ocp`

### Docker (recommended)

Pull the image and run it with your project directory mounted at `/ocp`:

```bash
docker pull raudssus/ocp:latest

docker run --rm -it \
  -v $(pwd):/ocp \
  -v ~/.ssh:/home/ocp/.ssh:ro \
  raudssus/ocp init --hetzner
```

Every `ocp` command below is that same pattern:
`docker run --rm -it -v $(pwd):/ocp raudssus/ocp <command>`. To type it as if
`ocp` were installed, set an alias for your shell session:

```bash
# Linux (--net=host lets the container reach your host's localhost, e.g. for
# --provider local; TZ/LANG make timezone/locale detection work)
alias ocp='docker run --rm -it --net=host -v $(pwd):/ocp \
  -e TZ=${TZ:-$(cat /etc/timezone 2>/dev/null || echo UTC)} -e LANG raudssus/ocp'

# Mac/Windows (host.docker.internal is reachable automatically, no --net=host)
alias ocp='docker run --rm -it -v $(pwd):/ocp raudssus/ocp'
```

With the alias set, `ocp init --hetzner`, `ocp apply`, `ocp status`, etc. all
work as plain commands for the rest of this guide. Mount `~/.ssh` read-only
(`-v ~/.ssh:/home/ocp/.ssh:ro`) whenever a command needs to reach an
`ssh`/`local` provider host.

### From source (development)

```bash
git clone git@github.com:Getty/kubernetes-ocp.git
cd kubernetes-ocp
cpanm --installdeps .
perl -Ilib bin/ocp --help
```

This is for hacking on OCP itself. It is **not** the Docker-first, pinned
path `make test` uses — see "Developing / building" below.

## Quickstart

Run these from an empty project directory. Every command that touches SSH or
the cluster prints what it needs (PIN1/PIN2 — see "Security model" below);
just follow the prompts.

1. **Initialize the project.**

   ```bash
   ocp init --hetzner
   ```

   Creates `ocp.yaml`, generates encrypted SSH keys (`keys.yaml`) and an age
   key (`age.key.enc`), initializes a git repo, and prompts for PIN1 and PIN2.
   `--hetzner` additionally asks for your Hetzner API token and lets you pick
   a location and server type from the live Hetzner catalogue (Enter keeps
   the sensible default). Without `--hetzner` you get the same `ocp.yaml`
   offline, with a reminder to add a token before `ocp apply`.

   Using your own server instead of Hetzner? See "Provider modes" below —
   `ocp init --provider ssh --host yourserver.com` or
   `ocp init --provider local`.

2. **Review/edit the spec.**

   ```bash
   vim ocp.yaml
   ```

   The generated file is already valid and deployable as-is. Open it to
   confirm the cluster `name`, distribution (`rke2` or `k3s`), and control
   plane size/location. See "`ocp.yaml` reference" below for every field.

3. **Deploy.**

   ```bash
   ocp apply
   ```

   > **HAZARD:** this creates real, billed Hetzner servers (or installs
   > Kubernetes on the server you named). Do not run it against a project
   > you don't intend to pay for / actually deploy to.

   In secure mode this prompts for PIN2 — control-plane deployment always
   needs the admin key. (In dev mode / `--nopassword` there's no PIN at
   all.) It then creates the control plane server, installs RKE2/K3s +
   Cilium, and deploys the registry cache, cert-manager and (if configured)
   the GPU stack and `robocop`. Takes several minutes. You should see a
   final cluster-health report at the end.

4. **Check status.**

   ```bash
   ocp status
   ```

   Prints the spec summary, the live node table (name, Ready/NotReady,
   roles, kubelet version, IP), GPU capacity if any, and a drift report if
   the running cluster has diverged from `ocp.yaml`/the pinned versions.
   Read-only — never prompts for a PIN, never changes anything.

5. **Get a kubeconfig.**

   ```bash
   ocp kubeconfig -e
   ```

   Merges the cluster's credentials into `$KUBECONFIG` (first path) or
   `~/.kube/config`, keeping any other clusters already there, and backs up
   the previous file. Running this inside the Docker container merges into
   the *container's* home, which disappears on exit — in that case use
   `ocp kubeconfig > ~/.kube/config` on the host instead.

6. **Use the cluster.**

   ```bash
   kubectl get nodes
   ```

   `kubectl` is not part of OCP (OCP itself never shells out to it — all
   Kubernetes access goes through `Kubernetes::REST`/`IO::K8s`), but it ships
   in the Docker image for you to poke around with, or use your own.

7. **Tear it down when you're done.**

   ```bash
   ocp destroy
   ```

   > **HAZARD:** deletes the real servers this project created (or
   > uninstalls Kubernetes from an `ssh`/`local` host) after a
   > confirmation prompt. `--force` skips the prompt. Never run this against
   > a cluster you still need.

   Never run any of the commands in this guide against a real project unless
   you mean it — `ocp apply` and `ocp destroy` are the only two that touch
   paid infrastructure or a live install.

## `ocp.yaml` reference

Keys are **snake_case only** — there is no key normalization, so
`controlPlanes:` or `k8s:` are silently ignored, not aliased. Minimal
annotated example:

```yaml
name: mycluster                # cluster name; also the "ocp-cluster" label

kubernetes:
  dist: rke2                   # rke2 (default) or k3s
  version: ''                  # empty = OCP::Versions' pinned default,
                                # not "latest upstream"

control_planes:                # Hash (1 CP), Hash + `nodes: N` (N identical
  provider: hetzner             # CPs), or an Array of hashes (mixed).
  server_type: cx32             # NOTE: today only the FIRST entry is ever
  location: fsn1                # deployed — see "Honest limits" below.
  image: debian-13

workers:                       # optional pools; each becomes Pending OCPNode
  - name: pool1                 # CRs on `ocp apply` (CR-first — see below)
    provider: hetzner
    server_type: cpx21
    nodes: 3

ssh:
  private_key: .ocp/id_ed25519
  public_key: .ocp/id_ed25519.pub

robocop: true                  # optional; default false, auto-true when any
                                # control plane or worker pool uses hetzner

network:                       # optional; Cilium LB-IPAM + L2 announcement
  lb_pool:
    cidr: 10.0.0.240/28          # or: start / stop
  l2:
    interfaces: ['^eth[0-9]+$']  # anchored regexes; default covers eth*/en*

lbipam: false                  # optional, default false; the default LB pool
                                # takes over the host IP via ARP, breaking
                                # sshd/apiserver — opt in only with a plan

gpu:
  enabled: true                 # default true; false skips GPU entirely
  driver: host                  # host (Rex installs it) | operator (GPU
                                 # Operator's driver DaemonSet)
  toolkit: true                 # default true; NVIDIA container toolkit

ssl:
  email: admin@example.com      # enables Let's Encrypt issuers; omit for
                                 # self-signed only (avoids ACME rate limits)

registry:
  name: ocp.internal            # local registry hostname (default)
  cache: ''                     # external docker.io pull-through cache URL
  upstream: ''                  # what the built-in cache pulls from

system:                        # detected from the host at `ocp init`
  timezone: Europe/Berlin
  locale: de_DE.UTF-8
  ntp: true

nocert: false                  # true disables cert-manager entirely
```

**`workers:` is input, not state.** On the first `ocp apply`, each pool is
translated into `OCPNodeProvider`/`OCPNode` CRs in the cluster; `ocp.yaml`'s
`workers:` section is never read again after that. From then on, manage nodes
imperatively (see "Common tasks" below) or by editing the CRs directly — the
robocop controller (or the CLI fallback) reconciles them.

**Provider modes** (`provider:` on a control plane or worker pool):

| Provider | What it does |
|---|---|
| `hetzner` | Creates/destroys real Hetzner Cloud servers via the API. Idempotent, matched by label. |
| `ssh` | Uses an existing server you already have. Requires `host:`. OCP never creates or deletes this machine — it only installs/uninstalls Kubernetes on it. |
| `local` | Same as `ssh`, but every provider operation (checks, uninstall) runs directly on this machine instead of over SSH. The Kubernetes install itself still goes through Rex over SSH to `127.0.0.1`, so the admin public key must still be in this machine's `~/.ssh/authorized_keys`. |

## Security model (PIN1/PIN2)

OCP has two modes, chosen once at `ocp init`:

- **Secure mode (default).** Every secret (`age.key.enc`, `keys.yaml`,
  `secrets.yaml`, `kubeconfig.yaml`) is encrypted and safe to commit to git.
  Two independent PINs protect it:
  - **PIN1** unlocks `age.key.enc`, the master key behind every encrypted
    file. Without it, nothing in the project is readable — this is the outer
    gate, by design.
  - **PIN2** unlocks only the **private half of the admin SSH key** inside
    `keys.yaml`. That admin key is the *only* key any `ocp` command uses to
    reach a machine — on Hetzner, SSH, or local, control plane or worker.
    There is also a `robo-ssh` (automation) key, protected by PIN1 alone, but
    nothing currently deploys its public half onto any machine (see
    "robocop" below) — so it is not a second way in.
  - `ocp apply`, `ocp ssh`, `ocp update`, `ocp node add`, and `ocp destroy`
    (when an `ssh`/`local` node is involved) prompt for PIN2. `ocp status`
    and any `--dry-run` never prompt — they open no SSH connection.
- **Dev mode (`ocp init --nopassword`).** A single unencrypted SSH key at
  `.ocp/id_ed25519`, no PIN prompts ever. `kubeconfig.yaml` is still
  encrypted even in this mode. Use only for local experiments, never for
  anything you'd mind losing.

**Files meant to be committed to git** (all encrypted, safe in a public
repo): `ocp.yaml`, `keys.yaml`, `secrets.yaml`, `age.key.enc`,
`kubeconfig.yaml`. **`.ocp/`** is local, gitignored state (decrypted key
cache, runtime status) and must never be committed.

Print the admin public key any time (e.g. to paste into an `ssh`/`local`
server's `authorized_keys`):

```bash
ocp keys show --purpose admin
```

Lost PIN1 = everything is unreadable, no recovery inside OCP (by design).
Lost PIN2 = the admin key, and therefore SSH to every machine in the
cluster, is gone for good with no recovery inside OCP either (out-of-band
console access is the only way back). Losing `.ocp/` alone is harmless — a
fresh `git clone` plus PIN1 regenerates it.

## robocop (the in-cluster controller)

`robocop` runs inside the cluster (namespace `ocp-system`) and reconciles
worker `OCPNode` CRs — provisioning the machine, installing Kubernetes,
joining it. It's opt-in: `robocop: true|false` in `ocp.yaml`, defaulting to
on whenever any control plane or worker pool uses the `hetzner` provider,
off otherwise. `ocp apply` deploys it automatically when it's enabled; you
can also deploy or redeploy it standalone:

```bash
ocp deploy-robocop
```

For robocop to join workers it needs the cluster's join token and the
private automation (robo) SSH key. `robocop.security_level` in `ocp.yaml`
controls how that material reaches it:

```yaml
robocop:
  enabled: true
  security_level: secret   # secret (default) | secret_approved | inject
```

- **`secret`** (default) — `ocp deploy-robocop` decrypts the credentials
  with PIN1 and writes them into a `robocop-credentials` Kubernetes Secret.
  A pod restart self-heals from that Secret.
- **`secret_approved`** — same as `secret`, but writing the Secret
  additionally requires an explicit PIN2 approval prompt.
- **`inject`** — **not available yet.** The config accepts the value, but
  `ocp deploy-robocop` refuses to run with it
  (`robocop.security_level 'inject' is not yet available (k2)`). The idea is
  in-memory-only delivery with nothing ever persisted to a Secret; it's
  deferred until that work lands.

## Common tasks

Add a worker without touching `ocp.yaml` (creates an `OCPNode` CR and waits
for it to become `Ready`):

```bash
ocp node add worker-1 --role worker
ocp node ls
ocp node rm worker-1
```

Register an additional provider imperatively:

```bash
ocp provider add --name hetzner-a --type hetzner --token-file token.txt --default
ocp provider ls
```

Check for drift and update fixable components (Cilium, cert-manager) to the
versions this OCP release pins:

```bash
ocp status            # shows drift, if any, and how much of it is fixable
ocp update --dry-run  # preview
ocp update             # apply
```

SSH into a node with the key it trusts:

```bash
ocp ssh --node police1
```

Roll out a new `robocop` container image without a full `ocp apply`:

```bash
ocp deploy-image --tag v1.2.3
```

## Honest limits

- **Only the first control plane is deployed.** `ocp.yaml` can express
  multiple control planes (`nodes: N`, or an array), but `ocp apply`
  currently bootstraps only the first one (`police1`) and prints a loud
  warning on STDERR if more are configured. Multi-CP is planned, not built.
- **`robocop.security_level: inject` doesn't work yet.** Use `secret` or
  `secret_approved`.
- **Docker-first, not just Docker-recommended.** `carton install`, `cpm`,
  regenerating `cpanfile.snapshot`, and the binding test suite all run
  inside the Docker image, never on the host — the Makefile has a target
  for each; there is deliberately no host-CPAN equivalent for the binding
  ones.
- **Not on CPAN.** This distribution builds with `no_cpan = 1`; `cpanm OCP`
  will never find it. Use the Docker image or a git checkout.
- **No `kubectl` in any OCP code path**, ever — only `Kubernetes::REST`/
  `IO::K8s`. `kubectl` in the Docker image is for you to debug with by hand.

## Developing / building

```bash
make test          # binding suite, runs inside Docker against cpanfile.snapshot
make test-v        # same, verbose
make test TESTS=t/33-registry-manifests.t   # a single file
make test-host     # fast, NOT binding — host CPAN state, may drift from the image
make build         # build the Docker image
make snapshot      # regenerate cpanfile.snapshot (inside Docker; never on host)
make docker-test   # confirm the built image starts and its entrypoint answers
```

`make smoke` bootstraps a full cluster against a **real machine** and wipes
whatever is on it (`SMOKE_HOST=...`) — human-triggered only, never run as
part of normal development, and its concerns never move into `t/`.

Releasing (`dzil release`, `make docker-push`, `make docker-release`) needs
the maintainer's explicit go-ahead and is out of scope for this guide.

**Output channels:** `ocp` commands separate STDOUT (payload/progress a
human or script reads) from STDERR (diagnostics, PIN prompts, warnings).
Machine-readable commands like `ocp keys show` and `ocp kubeconfig` put
*only* the requested material on STDOUT, so they compose in a pipe:

```bash
ocp keys show --purpose admin >> ~/.ssh/authorized_keys
```

## Links

- Repository: https://github.com/Getty/kubernetes-ocp
- Docker Hub: https://hub.docker.com/r/raudssus/ocp
- License: Perl 5
