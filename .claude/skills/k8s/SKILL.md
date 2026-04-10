---
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
- Build paths via `_build_resource_path()` for CRDs, `$api->_build_path()` for registered types
- Multi-document YAML: parse with `YAML::XS::Load()`, apply each resource

## Typed API (IO::K8s)

OCP registers typed resource providers:

```perl
$api->k8s->add('IO::K8s::Cilium', 'IO::K8s::CertManager', 'IO::K8s::GatewayAPI');
```

- Use `$api->list('Node')`, `$api->get('Deployment', $name, namespace => $ns)`
- CRDs without IO::K8s classes: use raw `$api->_request('GET', $path)` and `JSON::PP::decode_json`
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

```perl
my $path = '/apis/nvidia.com/v1/clusterpolicies/gpu-cluster-policy';
my $response = $api->_request('GET', $path);
my $obj = JSON::PP::decode_json($response->content) if $response->status < 400;
```

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
