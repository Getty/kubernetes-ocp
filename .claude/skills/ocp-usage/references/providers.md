# Provider Modes

Read when: choosing or debugging a provider mode (Hetzner, SSH, Local).

## Provider Modes

### Hetzner Cloud
- `ocp init --hetzner` prompts for the API token; `--provider hetzner` alone
  does not.
- Servers created via API, idempotent by labels: `ocp-cluster=<name>`,
  `ocp-role=control-plane|worker`, `ocp-node=<nodename>`.

### SSH (existing servers)
- `ocp init --provider ssh --host myserver.com` — `--host` is required.
  Hetzner, not ssh, is the init default, so `--provider ssh` without
  `--host` dies immediately.
- Node name = hostname up to the first dot (`avatar.conflict.industries` →
  `avatar`); same rule for ssh worker pools.
- **A worker by name (`ocp node add --host NAME`, k236):** with robocop on, the
  name is resolved by robocop inside the cluster (CoreDNS, then the node's
  resolver), not by the CLI host. A name that only resolves here (`/etc/hosts`,
  a container's `--add-host`) is invisible to every pod, so the join fails.
  `ocp node add` says so on STDERR (not for an IP). A name that does not
  resolve is reported as that, never as a rejected key: "Name 'X' does not
  resolve … This is not a key problem" (host-probe warning, `OCP::SSH`
  `wait_for_ssh`/`learn_host_key`, robocop's `status.message`; recogniser
  `OCP::SSH->name_unresolved`). Recommendation: pass the IP, or a DNS entry the
  cluster knows.
  **Without robocop (CLI path, k238)** the name is checked BEFORE any cluster
  write: resolution on this machine, then (not with `--nowait`) the usual SSH
  probe with the join's wait (~120 s). Failure prints "Name 'X' does not
  resolve: the lookup failed on this machine …" or the SSH error on STDERR,
  exit 1, and no OCPNode or other object is created (nothing to clean up, no
  `node rm --keep-machine`). `--nowait` checks resolution only; IPs are never
  resolved. With robocop on, unchanged: OCPNode as request, STDERR warning,
  `Failed` with a message if the cluster cannot resolve it.
- Destroy runs Rex::Rancher's uninstall line over SSH: every RKE2/K3s
  uninstaller present, then `/usr/local/bin/cilium`, `/opt/cni`, `/run/k3s`
  and Cilium's datapath; RKE2/K3s still installed, or Cilium state that
  survived (reboot needed), fails it with the reason.

### Local
- `OCP::Provider::Local`: provider operations run locally (open3), but
  `resolve_host` returns `127.0.0.1` so the actual install still goes through
  the normal Rex/SSH path.
