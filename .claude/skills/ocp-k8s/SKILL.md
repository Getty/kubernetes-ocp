---
name: ocp-k8s
description: Use when OCP applies Kubernetes resources from Perl — Server-Side Apply, IO::K8s typed objects, hash-based reconciliation, CRD resource paths.
model: sonnet
---

# Kubernetes Patterns for OCP

## Server-Side Apply

OCP uses Server-Side Apply (SSA) exclusively for all K8s resource management:

```perl
$api->_request('PATCH', $path, $resource,
    content_type => 'application/apply-patch+yaml',
    parameters   => { fieldManager => 'ocp', force => 'true' },
);
```

- Always use `fieldManager => 'ocp'` and `force => 'true'`
- Build paths via `_build_resource_path()` for CRDs, `$api->build_path()` for registered types (the public one, k420)
- Multi-document YAML: parse with `YAML::XS::Load()`, apply each resource

## Typed API (IO::K8s)

OCP registers typed resource providers:

```perl
$api->k8s->add('IO::K8s::Cilium', 'IO::K8s::CertManager', 'IO::K8s::GatewayAPI');
```

- Use `$api->list('Node')`, `$api->get('Deployment', $name, namespace => $ns)`
- A CustomResourceDefinition is a typed read too, see "CRD Access Pattern"
- Custom resources without IO::K8s classes: `crd_get`, see "CRD Access Pattern"
- New objects: `$api->new_object('Job', metadata => {...}, spec => {...})`

## Hash-Based Reconciliation

Components track deployment state via MD5 hashes in `.ocp/deployed.yaml`:

```perl
my $hash = Digest::MD5::md5_hex($manifest);
my $deployed = $self->_load_deployed_hashes($config);
return if ($deployed->{$component} // '') eq $hash;

# ... apply ...
$self->_save_deployed_hash($config, $component, $hash);
```

Always check both hash AND actual resource existence (hash match alone doesn't guarantee resources exist).

## _poll_deployment_ready Pattern

Standard polling for Deployment availability:

```perl
$self->_poll_deployment_ready($api, $name, $namespace, $timeout_seconds)
```

Returns 1 if availableReplicas > 0 within timeout, 0 otherwise. Polls every 5s.

## Resource Path Building

```perl
# For CRDs and unregistered types:
sub _build_resource_path {
    my ($self, $resource) = @_;
    # /apis/$apiVersion/namespaces/$ns/$plural/$name (namespaced)
    # /apis/$apiVersion/$plural/$name (cluster-scoped)
    # /api/v1/... (core API)
}
```

Pluralization: standard K8s rules (s, es, ies).

## CRD Access Pattern

**A CustomResourceDefinition** is a typed `get('CustomResourceDefinition', name => …)` (k471),
never a `/customresourcedefinitions/` path (t/406 fails on one):

```perl
my $crd = OCP::Drift->cluster_crd($api, 'ocpnodes.ocp.internal');   # plain hashref
```

- `OCP::Drift->cluster_crd($api, $name)` returns the CRD as a plain hashref
  (`object_to_struct`), `undef` only on 404, and dies with the client's error otherwise.
- Writers (apply, deploy-robocop) use `OCP::Cmd::Apply::K8s::crd_read($self, $api, $name)`
  (through the `_crd_read` wrappers in `Apply.pm` / `DeployRobocop.pm`, which tests override):
  same result, but a non-404 failure dies `could not read CustomResourceDefinition <name>: <cause>`.
- Neither calls `_request`.

**Custom resources without IO::K8s classes** (Gateway, nvidia ClusterPolicy, ResourceSlice
list, LB-IPAM pool list) go through `crd_get($self, $api, $path)` in `OCP::Cmd::Apply::K8s`
(wrapper `_crd_get`): a raw `_request('GET', $path)`, decoded. `undef` only on 404; any other
failure, or a non-JSON body, dies with the cause.

```perl
my $policy = $self->_crd_get($api, '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy');
```

**`_request` is the one sanctioned private call into Kubernetes::REST** (allowlist `%ESCAPE`
in t/406): SSA of a manifest, `crd_get`, and the robocop pod DELETE with `gracePeriodSeconds`
in `Apply/CR.pm` (Kubernetes::REST `delete` lacks it, k420). Any other `->_name` call on
Kubernetes::REST fails t/406.

## Namespace Creation

Always ensure namespace exists before deploying resources:

```perl
push @resources, {
    apiVersion => 'v1',
    kind       => 'Namespace',
    metadata   => { name => 'my-namespace' },
};
```

SSA is idempotent - applying existing namespace is safe.
