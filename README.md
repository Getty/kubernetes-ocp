# OCP — Omni Control Plane

![OCP — Omni Control Plane: come quietly, or there will be reconciliation](assets/github.jpg)

**One command, one config file, a complete Kubernetes cluster.**

OCP is a CLI that builds and looks after Kubernetes clusters — on Hetzner Cloud
servers it creates for you, or on machines you already own. You describe the
cluster you want in one YAML file; `ocp apply` makes it real, and keeps it
that way.

It is not a wrapper that leaves you with a bare cluster and a reading list.
What comes up is a cluster you can put a workload on: networking, ingress,
certificates, an image registry and — if there is an NVIDIA card in the machine
— the whole GPU stack, all at versions this release has pinned and tested
together.

There are two pieces. **`ocp`** is what you run from your laptop or CI: it
bootstraps the control plane and reconciles the cluster. **`robocop`** is a
small controller that runs *inside* the cluster and manages worker nodes, so
nodes can come and go while your laptop is closed.

This README takes you from nothing to a running cluster and back, with
copy-paste commands. No prior Kubernetes, RKE2 or Cilium knowledge assumed.

---

## What you get

`ocp apply` installs all of this, in this order, because each piece depends on
the one before it:

| | Component | What it is for |
|---|---|---|
| **1** | **RKE2** (or K3s) | The Kubernetes distribution itself. Pinned version, not "whatever is newest". Pick either — OCP treats them as equals. |
| **2** | **Registry cache + local registry** | `ocp-cache` pulls through to docker.io so image pulls stop hammering the internet; `ocp-registry` is an in-cluster store for your own images. CoreDNS is patched so `registry.local` resolves. Comes up first — everything else pulls through it. |
| **3** | **Node Feature Discovery** | Labels each node with what the hardware actually is. Always installed; the GPU step reads its labels. |
| **4** | **NVIDIA GPU stack** | GPU Operator, container toolkit, device plugin and DCGM exporter — installed **only** when NFD reports an NVIDIA card. No card, no GPU pods, no noise. |
| **5** | **cert-manager** | Issues TLS certificates. Self-signed out of the box; add `ssl.email` to `ocp.yaml` and you get Let's Encrypt issuers too. |
| **6** | **Cilium** | The entire network layer: eBPF CNI, kube-proxy *replaced* (not supplemented), Gateway API for ingress, and LB-IPAM to hand out LoadBalancer IPs. |
| **7** | **CRDs + `robocop`** | `OCPNode` and `OCPNodeProvider` resources, and the controller that reconciles them, so the cluster can grow and shrink on its own. |

At the end, `ocp apply` does not just report that its own steps finished. It
asks the cluster whether it is actually healthy and tells you the truth either
way.

## What OCP takes care of

The things you would otherwise have to remember yourself:

- **Every version is pinned, exactly once.** Kubernetes, Cilium, the Gateway
  API CRD bundle, cert-manager, every GPU component. `ocp version` prints the
  set in effect. Components that must move together (Cilium and its Gateway API
  CRDs, for instance) are pinned together.
- **It notices when reality drifts.** `ocp status` compares the running cluster
  against your spec and the pinned versions, and says what diverged. `ocp
  update` closes the gap for what can be fixed in place.
- **Your spec lives in git; the cluster's status does not.** `ocp.yaml` is what
  you want. What *is* gets read back from the cluster, never cached into your
  config behind your back.
- **Secrets are encrypted and meant to be committed.** Keys, tokens and
  kubeconfig are age/SOPS-encrypted in the project directory. You commit them.
  Two PINs stand in front — see [the security model](docs/security.md).
- **Re-running is safe.** `ocp apply` is idempotent. Run it again after editing
  `ocp.yaml`, or when you are not sure what state something is in.
- **No `kubectl` anywhere in OCP.** Every Kubernetes call goes through the Perl
  API client. `kubectl` ships in the image purely so *you* can poke around.

---

## Before you start

You need three things.

**1. Docker.** OCP's toolchain is Docker-first. The image bundles everything —
Perl, every CPAN dependency, and `kubectl` for manual debugging. There is
nothing else to install.

**2. Somewhere to put a cluster.** Either:

- a **Hetzner Cloud API token** — Hetzner Cloud console → your project →
  Security → API tokens. OCP creates and destroys the servers for you; or
- **a server you can SSH into as root** — bare metal, a VM, or your own
  laptop. OCP installs Kubernetes onto it but never creates or deletes the
  machine itself.

**3. An empty directory.** Everything OCP writes — `ocp.yaml`, encrypted keys,
local state — lives there, and it becomes a git repository:

```bash
mkdir mycluster && cd mycluster
```

> **Note:** OCP is deliberately not published on CPAN. `cpanm OCP` will not
> find it. Use the Docker image, or a git checkout for
> [development](docs/development.md).

---

## Step 1 — Make `ocp` a command

Everything below is one Docker container run with your project directory
mounted at `/ocp`. Rather than typing that every time, set an alias for your
shell session:

**Linux:**

```bash
alias ocp='docker run --rm -it --net=host -v $(pwd):/ocp \
  -v ~/.ssh:/home/ocp/.ssh:ro \
  -e TZ=${TZ:-$(cat /etc/timezone 2>/dev/null || echo UTC)} -e LANG \
  raudssus/ocp'
```

**macOS / Windows:**

```bash
alias ocp='docker run --rm -it -v $(pwd):/ocp \
  -v ~/.ssh:/home/ocp/.ssh:ro raudssus/ocp'
```

What each part is doing, so you can adjust it with confidence:

| Flag | Why |
|---|---|
| `-v $(pwd):/ocp` | Your project directory. The alias uses `$(pwd)` at *call* time, so `ocp` always acts on the directory you are standing in. |
| `-v ~/.ssh:...:ro` | Read-only, so commands can reach an `ssh`/`local` provider host. Not needed for a pure Hetzner cluster. |
| `--net=host` (Linux) | Lets the container reach your host's own localhost — needed for `--provider local`. On macOS and Windows, `host.docker.internal` handles this without the flag. |
| `-e TZ` / `-e LANG` | So the cluster gets your timezone and locale rather than the container's. |
| `--rm -it` | Throw the container away afterwards; keep an interactive terminal for the PIN prompts. |

Check that it works:

```bash
ocp --help
```

Prefer to make it permanent? Put the alias in your `~/.bashrc` or `~/.zshrc`.
To pin a specific version instead of tracking `latest`, use a tag:
`raudssus/ocp:v0.001`.

The same image is published to a second location, so you are never stuck
waiting for one registry to come back:

```bash
docker pull raudssus/ocp                    # Docker Hub — the default
docker pull ghcr.io/getty/kubernetes-ocp    # GitHub Container Registry
```

Both are built and pushed by the same CI run from the same commit. Use
whichever you prefer; the rest of this guide assumes the Docker Hub name.

## Step 2 — Create your project

```bash
ocp init --hetzner
```

This asks for your Hetzner API token, then lets you pick a location and server
type from Hetzner's live catalogue (pressing Enter keeps a sensible default).
Then it asks you to choose **PIN1** and **PIN2** — two separate PINs, and it is
worth understanding what they protect before you invent them:
[the security model](docs/security.md). Short version: PIN1 unlocks the
project, PIN2 unlocks SSH access to your machines. Neither can be recovered.

When it finishes, the directory contains:

```
ocp.yaml            your cluster spec — commit this
keys.yaml           SSH keys, encrypted — commit this
secrets.yaml        API token, encrypted — commit this
age.key.enc         the master key, PIN1-protected — commit this
.ocp/               local cache and state — gitignored, never commit
```

Using your own server instead of Hetzner:

```bash
ocp init --provider ssh --host yourserver.example.com
ocp init --provider local                            # this very machine
```

Both need OCP's admin public key in the target's `authorized_keys`. Print it
with `ocp keys show --purpose admin`. No `--hetzner` and no `--provider` gives
you the same `ocp.yaml` offline, with a reminder to add a token before you
deploy.

## Step 3 — Look at `ocp.yaml`

```bash
vim ocp.yaml
```

The generated file is already valid and deployable as-is, so this step is
optional — but it is the file the whole tool revolves around, so it is worth
thirty seconds. Confirm the cluster `name`, the distribution (`rke2` or `k3s`),
and the control plane's size and location.

Two things that catch people out:

- **Keys are snake_case only.** `control_planes`, not `controlPlanes`. There is
  no aliasing — a misspelled key is silently ignored, not corrected.
- **An empty `version:` means OCP's pinned version**, not "latest upstream".
  That is the point: you get the combination that was tested together.

Every field is documented in the [`ocp.yaml` reference](docs/configuration.md).

## Step 4 — Deploy

```bash
ocp apply
```

> **This creates real, billed servers** (or installs Kubernetes onto the server
> you named). Only run it in a project you actually intend to deploy.

In secure mode this prompts once for **PIN2** — bringing up a control plane
always needs the admin key. Then it works through the list from
[What you get](#what-you-get), narrating each step as it goes. **Expect several
minutes**; most of it is waiting for the machine to boot and for images to pull
the first time.

At the end you get a health verdict about the *cluster*, not about the run: if
CoreDNS is crash-looping, `ocp apply` says so and exits non-zero, even though
every one of its own steps succeeded.

Something went wrong? Run it again. `ocp apply` is idempotent and picks up
where reality actually is.

## Step 5 — See what you got

```bash
ocp status
```

Prints your spec summary, the live node table (name, Ready/NotReady, roles,
kubelet version, IP), GPU capacity if there is any, and a drift report if the
running cluster has diverged from `ocp.yaml` or the pinned versions.

This command is read-only. It never prompts for a PIN, opens no SSH connection
and changes nothing — so it is always safe to run.

## Step 6 — Get a kubeconfig

```bash
ocp kubeconfig -e
```

Merges the cluster's credentials into `$KUBECONFIG` (first path) or
`~/.kube/config`, keeps any other clusters already in there, and backs up the
previous file.

> **Careful with the alias:** run inside the container, this merges into the
> *container's* home directory, which disappears the moment the command exits.
> To get the kubeconfig onto your actual machine, print it to STDOUT instead:
>
> ```bash
> ocp kubeconfig > ~/.kube/config
> ```

Now your own tools can talk to the cluster:

```bash
kubectl get nodes
```

## Step 7 — Run something on it

There is a complete example in [`eg/simple-webserver.yaml`](eg/simple-webserver.yaml)
— an nginx Deployment, a Service, and an `HTTPRoute` that publishes it through
the Cilium Gateway:

```bash
kubectl apply -f eg/simple-webserver.yaml
kubectl get pods
```

Then open `http://<your-node-ip>/` in a browser. If you see "It works!", your
CNI, your Gateway and your image pulls are all working — which is most of the
cluster proven in one shot.

More examples in [`eg/`](eg/), including HTTPS with Let's Encrypt.

## Step 8 — Add a worker node

Your control plane can run workloads on its own, but a real cluster grows.
Adding a node does not involve editing `ocp.yaml`:

```bash
ocp node add worker-1 --role worker
```

This writes an `OCPNode` custom resource and then waits, printing each phase as
the node passes through it: the machine is created, Kubernetes is installed, it
joins, it goes Ready. On Hetzner that is a few minutes. If `robocop` is running
in the cluster it does the work and the command just watches; if not, the CLI
drives it directly (and prompts once for PIN2, since it needs SSH to the new
machine).

Check the result:

```bash
ocp node ls
```

Columns: NAME, ROLE, PHASE, PROVIDER, IP, AGE.

Useful variations:

```bash
ocp node add gpu-1 --role worker --provider hetzner-default --gpu
ocp node add ssh-1 --role worker --provider ssh-default --host 10.0.0.5
ocp node add worker-2 --role worker --nowait     # write the CR, don't wait
```

Note that `--provider` takes the **name** of a provider resource
(`hetzner-default`), not a provider type (`hetzner`). `ocp provider ls` lists
what exists. With only one provider you can leave the flag off entirely.

> **`workers:` in `ocp.yaml` is input, not state.** It seeds the node
> resources on the *first* `ocp apply` and is never read again. After that,
> nodes are managed here, with `ocp node`.

## Step 9 — Remove a node

```bash
ocp node rm worker-1
```

This is a real teardown, in order and without shortcuts: the node is marked
`Terminating`, cordoned in Kubernetes, the provider's server is deleted, the
Kubernetes node object is removed, and finally the custom resource goes.

Get the name wrong and nothing happens — it refuses and lists the names that
do exist:

```
Unknown node 'wroker-1'.
Available: cp-lab, otho-gpu, worker-1
```

## Step 10 — Tear it down

```bash
ocp destroy
```

> **This deletes the real servers this project created** (or uninstalls
> Kubernetes from an `ssh`/`local` host). There is a confirmation prompt;
> `--force` skips it. Never point this at a cluster you still need.

`ocp apply` and `ocp destroy` are the only two commands in this guide that
touch paid infrastructure or a live install. Everything else is safe to run
while you are finding your way around.

---

## What else you can do

**Update components to the versions this release pins:**

```bash
ocp status              # what has drifted, and how much of it is fixable
ocp update --dry-run    # preview the changes
ocp update              # apply them
```

**SSH into a node,** with the key it already trusts:

```bash
ocp ssh --node police1
```

**Register another provider** without editing `ocp.yaml`:

```bash
ocp provider add --name hetzner-fsn1 --type hetzner --token-file token.txt --default
ocp provider ls
```

**Print the admin public key** — this is how you authorise OCP on a machine you
own. Only the key goes to STDOUT, so it pipes cleanly:

```bash
ocp keys show --purpose admin | ssh root@yourserver 'cat >> ~/.ssh/authorized_keys'
```

**Deploy or roll out `robocop`:**

```bash
ocp deploy-robocop            # deploy the controller and its CRDs
ocp deploy-image --tag v1.2.3 # new controller image, without a full apply
```

**See every version in play:**

```bash
ocp version
```

## What OCP can't do yet

Stated plainly, so nothing surprises you halfway through:

- **RKE2 deploys every control plane, but there is no HA client endpoint
  yet.** `ocp apply` bootstraps all of them (embedded-etcd join: the first as
  cluster-init, the rest joining as servers), and every control plane's
  address is in every control plane's TLS SANs — so etcd quorum survives one
  going down. What's still missing is a load balancer, VIP or DNS name in
  front of them: the kubeconfig and every other client keeps pointing at the
  first control plane's address, so losing that one machine still costs you
  API access even though the rest of the cluster is fine.
- **k3s does not support multiple control planes at all.** Configure more than
  one and `ocp apply` prints a loud warning and bootstraps only the first.
- **`robocop.security_level: inject` does not survive a pod restart.** The
  key lives only in robocop's memory; after a restart robocop is not Ready
  and holds back the OCPNodes that need SSH until you run `ocp inject-key`
  again. Use `secret` or `secret_approved` if workers must come up unattended.
- **A dev-mode project cannot move to secure mode.** Choose at `ocp init`.
- **Not on CPAN, ever.** This distribution builds with `no_cpan = 1`. Docker
  image or git checkout.

## Where to read more

| Document | What is in it |
|---|---|
| [`ocp.yaml` reference](docs/configuration.md) | Every configuration field, provider modes, version pinning |
| [Security model](docs/security.md) | PIN1/PIN2, the key layout, what belongs in git, what losing a PIN costs |
| [robocop](docs/robocop.md) | The in-cluster controller, and how credentials reach it |
| [Developing OCP](docs/development.md) | Build, test, the Docker-first toolchain, CI, releasing |
| [Architecture decisions](docs/adr/) | Why OCP is shaped the way it is, one decision per file |

## Links

- **Repository:** https://github.com/Getty/kubernetes-ocp
- **Container image:** `raudssus/ocp`
  ([Docker Hub](https://hub.docker.com/r/raudssus/ocp)), mirrored to
  `ghcr.io/getty/kubernetes-ocp`
- **License:** Perl 5
