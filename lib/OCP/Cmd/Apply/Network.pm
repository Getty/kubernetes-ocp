package OCP::Cmd::Apply::Network;
# ABSTRACT: Cluster ingress (cert-manager + Cilium Gateway + LB-IPAM + CoreDNS)

use strict;
use warnings;

use HTTP::Tiny;
use JSON::PP ();
use Socket;

use OCP::Drift;
use OCP::Versions;

# CoreDNS ConfigMap names per distribution. Stored here (and aliased into
# OCP::Drift) so the writer and the drift probe read the same list — a writer
# looking in "coredns" while the reader looks in "rke2-coredns-rke2-coredns"
# is exactly the silent no-op OCP::Drift's registry_dns_drift exists to catch.
our @COREDNS_CONFIGMAPS = @OCP::Drift::COREDNS_CONFIGMAPS;

=head1 SYNOPSIS

    OCP::Cmd::Apply::Network::apply_cert_manager($apply);
    OCP::Cmd::Apply::Network::wait_cert_manager_and_create_issuers($apply, $config);
    OCP::Cmd::Apply::Network::setup_cilium_gateway($apply, $config);
    OCP::Cmd::Apply::Network::setup_lb_ipam($apply, $node_ip);
    OCP::Cmd::Apply::Network::configure_registry_dns($apply, $node_ip);

    # Pure functions (no $self):
    my $patched = OCP::Cmd::Apply::Network::corefile_with_host($corefile, $ip, 'registry.local');

=head1 DESCRIPTION

The bits the apply path wires up *between* the cluster being reachable and
the registry being reachable by name:

- cert-manager (downstream manifest + the issuer CRs that follow it)
- the Cilium Gateway (HTTP+HTTPS, the LB-IPAM pool that hands it an IP,
  the L2 announcement that makes the IP reachable)
- the CoreDNS patch that turns registry.local into an address

The Corefile machinery is purely textual: t/39 feeds in the stock k3s and
RKE2 Corefiles and never tells C<_corefile_with_host> how the cluster was
built. That is the only reason it can be tested without a real cluster.

L<OCP::Cmd::Apply> re-exports every helper as a thin forwarder so the test
surface (t/31, t/39) keeps working.

=cut

sub apply_cert_manager {
    my ($self) = @_;

    my $api = $self->_k8s_api;

    my $version = OCP::Versions->get_component_version('cert_manager');
    my $url = "https://github.com/cert-manager/cert-manager/releases/download/$version/cert-manager.yaml";

    # Download manifest via HTTP

    my $http = HTTP::Tiny->new(timeout => 60);
    my $response = $http->get($url);
    die "Failed to download cert-manager manifest: $response->{status} $response->{reason}\n"
        unless $response->{success};

    # Parse multi-document YAML and server-side apply each resource
    $self->_apply_yaml_string($api, $response->{content});
}

sub wait_cert_manager_and_create_issuers {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Poll for cert-manager deployment to become available (up to 600s)
    unless ($self->_poll_deployment_ready($api, 'cert-manager', 'cert-manager', 600)) {
        die "cert-manager deployment not ready\n";
    }

    $self->_create_cert_issuers($config);
}

sub create_cert_issuers {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;
    my $email = $config->ssl_email;

    # Wait a bit for webhook to be fully ready (timing issue)
    print "      Waiting for cert-manager webhook to stabilize...\n";
    sleep 5;

    # Build issuer resources
    my @issuers = (selfsigned_issuer());

    if ($email) {
        print "      Creating Let's Encrypt issuers (email: $email)...\n";
        push @issuers, acme_issuer('letsencrypt-prod',
            'https://acme-v02.api.letsencrypt.org/directory', $email);
        push @issuers, acme_issuer('letsencrypt-staging',
            'https://acme-staging-v02.api.letsencrypt.org/directory', $email);
    }

    # Server-side apply each issuer (retry for webhook readiness)
    my (@created, @failed);
    for my $issuer (@issuers) {
        my $name = $issuer->{metadata}{name};

        # cert-manager's webhook can take ~30s after the Deployment reports
        # Ready — endpoints, then admissionregistration. 15s of retries was
        # not enough on a fresh install: the first three attempts all hit
        # "no endpoints available for service cert-manager-webhook" and the
        # whole run failed. 90s with backoff is enough in practice.
        my $retries = 12;
        my $error;
        for my $attempt (1..$retries) {
            if (eval { $self->_server_side_apply($api, $issuer); 1 }) {
                push @created, $name;
                undef $error;
                last;
            }
            $error = $@;
            if ($attempt < $retries) {
                my $delay = $attempt < 4 ? 5 : 10;
                print "      Webhook not ready (attempt $attempt/$retries), retrying in ${delay}s...\n";
                sleep $delay;
            }
        }
        push @failed, [$name, $error] if defined $error;
    }

    # Report what actually exists, not what we intended to create. This used to
    # print the planned list unconditionally, with failures going to a warn() on
    # stderr — so a run where no issuer was created at all still announced
    # "ClusterIssuers created: selfsigned-issuer" and looked clean in the log.
    print "      ClusterIssuers created: " . join(', ', @created) . "\n" if @created;

    if (@failed) {
        for my $f (@failed) {
            my ($name, $error) = @$f;
            chomp(my $msg = $error // 'unknown error');
            print "      [FAILED] ClusterIssuer $name: $msg\n";
        }
        die "cert-manager issuers not created: "
            . join(', ', map { $_->[0] } @failed) . "\n";
    }

    unless ($email) {
        print "      (Add 'ssl: { email: your\@email.com' } to ocp.yaml for Let's Encrypt)\n";
    }
}

sub selfsigned_issuer {
    return {
        apiVersion => 'cert-manager.io/v1',
        kind       => 'ClusterIssuer',
        metadata   => { name => 'selfsigned-issuer' },
        spec       => { selfSigned => {} },
    };
}

sub acme_issuer {
    my ($name, $server, $email) = @_;
    return {
        apiVersion => 'cert-manager.io/v1',
        kind       => 'ClusterIssuer',
        metadata   => { name => $name },
        spec       => {
            acme => {
                server             => $server,
                email              => $email,
                privateKeySecretRef => { name => $name },
                solvers            => [{
                    http01 => {
                        gatewayHTTPRoute => {
                            parentRefs => [{
                                name      => 'cilium-gateway',
                                namespace => 'kube-system',
                            }],
                        },
                    },
                }],
            },
        },
    };
}

sub setup_cilium_gateway {
    my ($self, $config) = @_;

    my $api = $self->_k8s_api;

    # Gateway API CRDs are already installed by Rexfile (before Cilium)

    # Create Cilium Gateway via server-side apply
    print "      Creating Cilium Gateway...\n";

    my $gateway = {
        apiVersion => 'gateway.networking.k8s.io/v1',
        kind       => 'Gateway',
        metadata   => { name => 'cilium-gateway', namespace => 'kube-system' },
        spec       => {
            gatewayClassName => 'cilium',
            listeners        => [
                {
                    name     => 'http',
                    port     => 80,
                    protocol => 'HTTP',
                    allowedRoutes => { namespaces => { from => 'All' } },
                },
                {
                    name     => 'https',
                    port     => 443,
                    protocol => 'HTTPS',
                    allowedRoutes => { namespaces => { from => 'All' } },
                    tls => {
                        mode            => 'Terminate',
                        certificateRefs => [{
                            kind      => 'Secret',
                            name      => 'default-gateway-cert',
                            namespace => 'kube-system',
                        }],
                    },
                },
            ],
        },
    };

    $self->_server_side_apply($api, $gateway);

    # Wait for the Gateway resource to be *Accepted* by the Cilium gateway
    # controller. We deliberately do NOT wait for Programmed=True: the HTTPS
    # listener references a cert-manager Secret that won't exist yet at this
    # point, so Programmed stays False until cert-manager finishes its work
    # later. Accepted is the "controller has claimed this Gateway" signal and
    # is enough for our setup ordering.
    print "      Waiting for Gateway to be Accepted by Cilium...\n";
    # Gateway is a CRD (gateway.networking.k8s.io), not a core resource —
    # $api->get('Gateway', ...) fails silently because Kubernetes::REST has
    # no IO::K8s class for it. Use raw API path instead.
    my $gw_path = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';
    for my $i (1..30) {
        my $gw = $self->_crd_get($api, $gw_path);
        if ($gw && $gw->{status} && $gw->{status}{conditions}) {
            for my $cond (@{ $gw->{status}{conditions} }) {
                if ($cond->{type} eq 'Accepted' && $cond->{status} eq 'True') {
                    print "      Gateway is accepted (Programmed will follow once cert-manager provides the Secret)\n";
                    return;
                }
            }
        }
        sleep 2;
    }
    die "Gateway 'cilium-gateway' did not become Accepted within 60s\n";
}

sub setup_lb_ipam {
    my ($self, $node_ip) = @_;

    my $api = $self->_k8s_api;

    # Resolve hostname to IP if needed

    if ($node_ip !~ /^\d+\.\d+\.\d+\.\d+$/) {
        my $packed = Socket::inet_aton($node_ip);
        die "Cannot resolve $node_ip\n" unless $packed;
        $node_ip = Socket::inet_ntoa($packed);
    }

    # If IP is localhost/loopback, get the real node IP from Kubernetes
    if ($node_ip =~ /^127\./) {
        my $nodes = eval { $api->list('Node') };
        if ($nodes && $nodes->items && @{ $nodes->items }) {
            for my $addr (@{ $nodes->items->[0]->status->addresses || [] }) {
                if ($addr->type eq 'InternalIP' && $addr->address !~ /^127\./) {
                    print "      Using node IP " . $addr->address . " (instead of $node_ip)\n";
                    $node_ip = $addr->address;
                    last;
                }
            }
        }
        if ($node_ip =~ /^127\./) {
            print "      WARNING: Only loopback IP available, LB-IPAM may not work externally\n";
        }
    }
    print "      LB-IPAM pool: $node_ip/32\n";

    # Wait for Cilium to serve the LB-IPAM API. In Cilium 1.19+ both
    # CiliumLoadBalancerIPPool and most BGP resources are served under v2;
    # CiliumL2AnnouncementPolicy is still v2alpha1. This matches the typed
    # classes in IO::K8s::Cilium 1.100.
    print "      Waiting for CiliumLoadBalancerIPPool API...\n";
    my $crd_ready = 0;
    for my $i (1..30) {
        my $resp = eval {
            $api->_request('GET', '/apis/cilium.io/v2/ciliumloadbalancerippools');
        };
        if ($resp && $resp->status < 400) {
            $crd_ready = 1;
            last;
        }
        print "      ... waiting for Cilium operator (${i}/30)\n" if $i % 5 == 0;
        sleep 10;
    }
    die "CiliumLoadBalancerIPPool API (cilium.io/v2) not served after 300s\n"
        unless $crd_ready;

    my @resources = (
        {
            apiVersion => 'cilium.io/v2',
            kind       => 'CiliumLoadBalancerIPPool',
            metadata   => { name => 'default-pool' },
            spec       => { blocks => [{ cidr => "$node_ip/32" }] },
        },
        {
            apiVersion => 'cilium.io/v2alpha1',
            kind       => 'CiliumL2AnnouncementPolicy',
            metadata   => { name => 'default-l2' },
            spec       => {
                interfaces      => ['^eth[0-9]+', '^en[a-z0-9]+'],
                externalIPs     => JSON::PP::true,
                loadBalancerIPs => JSON::PP::true,
            },
        },
    );

    $self->_server_side_apply_all($api, @resources);

    # Verify Gateway got an IP (raw CRD get — Gateway has no IO::K8s class)
    sleep 2;
    my $gw_path = '/apis/gateway.networking.k8s.io/v1/namespaces/kube-system/gateways/cilium-gateway';
    my $gw = $self->_crd_get($api, $gw_path);
    if ($gw && $gw->{status} && $gw->{status}{addresses} && @{ $gw->{status}{addresses} }) {
        print "      Gateway external IP: $gw->{status}{addresses}[0]{value}\n";
    }
}

sub configure_registry_dns {
    my ($self, $node_ip) = @_;

    my $api = $self->_k8s_api;

    # Resolve to IP if hostname. Through OCP::Drift, because `ocp status`
    # reports on this record and has to arrive at the same address from the
    # same starting value — a project whose control plane is a DNS name
    # (control_planes: host:) otherwise reads as permanently drifted.
    $node_ip = OCP::Drift::resolve_address($node_ip)
        // die "Cannot resolve $node_ip\n";

    # Get current CoreDNS ConfigMap
    my ($cm_name, $cm);
    for my $candidate (@COREDNS_CONFIGMAPS) {
        $cm = eval { $api->get('ConfigMap', $candidate, namespace => 'kube-system') };
        next unless $cm;
        $cm_name = $candidate;
        last;
    }
    return 0 unless $cm;

    my $corefile = $cm->data->{Corefile} // '';
    my $patched  = corefile_with_host($corefile, $node_ip, 'registry.local');

    # Already resolves to this node
    return 0 if $patched eq $corefile;

    # Patch the ConfigMap via server-side apply
    $self->_server_side_apply($api, {
        apiVersion => 'v1',
        kind       => 'ConfigMap',
        metadata   => { name => $cm_name, namespace => 'kube-system' },
        data       => { Corefile => $patched },
    });

    print "  [ok] CoreDNS configured for registry.local -> $node_ip\n";
    return 1;
}

#
# Point a name at an address in a Corefile.
#
# CoreDNS allows the hosts plugin only once per server block — a second one
# and it refuses to start with "plugin/hosts: this plugin can only be used
# once per Server Block", taking cluster DNS down with it. k3s ships a
# Corefile whose root block already runs hosts for /etc/coredns/NodeHosts (a
# file k3s' own controller owns and rewrites), RKE2's has no hosts plugin at
# all. So the record goes *into* an existing hosts block as an inline entry,
# and only a Corefile without one gets a block of its own.
#
sub corefile_with_host {
    my ($corefile, $ip, $hostname) = @_;

    # A cluster bootstrapped by an older OCP carries the block that broke it.
    # Take that back out first: the record inside it would otherwise read as
    # "already configured" and re-running apply would leave CoreDNS down.
    $corefile = corefile_drop_added_hosts($corefile, $hostname);

    my @lines = split /\n/, $corefile, -1;

    # Brace depth at the start of each line: 0 on a server block header,
    # 1 on the plugin lines inside it, 2 inside a plugin's config block.
    my @depth;
    my $level = 0;
    for my $i (0 .. $#lines) {
        $depth[$i] = $level;
        my $opens  = () = $lines[$i] =~ /\{/g;
        my $closes = () = $lines[$i] =~ /\}/g;
        $level += $opens - $closes;
    }

    my ($from, $to) = corefile_root_block(\@lines, \@depth);
    return $corefile unless defined $from;

    # Already listed somewhere in the block: only the address may need fixing
    for my $i ($from + 1 .. $to) {
        my ($indent, $rest) = $lines[$i] =~ /^(\s*)(\S.*?)\s*$/ or next;
        my @token = split /\s+/, $rest;
        next unless @token >= 2 && $token[0] =~ /^[0-9a-fA-F.:]+$/;
        next unless grep { $_ eq $hostname } @token[1 .. $#token];
        return $corefile if $token[0] eq $ip;
        $token[0] = $ip;
        $lines[$i] = $indent . join ' ', @token;
        return join "\n", @lines;
    }

    # One indentation step, as this Corefile writes it
    my $indent = '    ';
    for my $i ($from + 1 .. $to - 1) {
        next unless $depth[$i] == 1 && $lines[$i] =~ /^(\s+)\S/;
        $indent = $1;
        last;
    }

    # Merge into the hosts plugin the distribution already runs
    for my $i ($from + 1 .. $to) {
        next unless $depth[$i] == 1;
        my ($args, $open) = $lines[$i] =~ /^\s*hosts\b([^{]*?)\s*(\{?)\s*$/;
        next unless defined $args;

        if ($open) {
            my $inner = ($i < $#lines && $lines[$i + 1] =~ /^(\s+)\S/) ? $1 : "$indent$indent";
            splice @lines, $i + 1, 0, "$inner$ip $hostname";
        }
        else {
            # "hosts FILE" without a config block — wrap it around the entry,
            # adding no option that would change what the plugin already does
            splice @lines, $i, 1,
                "${indent}hosts$args {",
                "$indent$indent$ip $hostname",
                "$indent}";
        }
        return join "\n", @lines;
    }

    # No hosts plugin in this block: add one, in front of the first plugin
    # that has an opinion about names, or last if there is none
    my $at = $to;
    for my $i ($from + 1 .. $to - 1) {
        next unless $depth[$i] == 1 && $lines[$i] =~ /^\s*(?:ready|kubernetes)\b/;
        $at = $i;
        last;
    }

    splice @lines, $at, 0,
        "${indent}hosts {",
        "$indent$indent$ip $hostname",
        "$indent${indent}fallthrough",
        "$indent}";

    return join "\n", @lines;
}

#
# Undo the block an older OCP added: a hosts plugin that names no file and
# lists the record OCP itself writes. Only ever when the block is a duplicate,
# so a Corefile CoreDNS is happy with is never touched — and never the last
# hosts plugin standing, which is the distribution's own.
#
sub corefile_drop_added_hosts {
    my ($corefile, $hostname) = @_;

    my @lines = split /\n/, $corefile, -1;

    my @depth;
    my $level = 0;
    for my $i (0 .. $#lines) {
        $depth[$i] = $level;
        my $opens  = () = $lines[$i] =~ /\{/g;
        my $closes = () = $lines[$i] =~ /\}/g;
        $level += $opens - $closes;
    }

    my ($from, $to) = corefile_root_block(\@lines, \@depth);
    return $corefile unless defined $from;

    my @hosts = grep { $depth[$_] == 1 && $lines[$_] =~ /^\s*hosts\b/ } ($from + 1 .. $to);
    return $corefile if @hosts < 2;

    my $left = scalar @hosts;
    for my $i (reverse @hosts) {
        last if $left < 2;
        next unless $lines[$i] =~ /^\s*hosts\s*\{\s*$/;

        my $end = $i;
        $end++ while $end < $to && $depth[$end + 1] > $depth[$i];
        next unless grep { /\b\Q$hostname\E\b/ } @lines[$i + 1 .. $end];

        splice @lines, $i, $end - $i + 1;
        $left--;
    }

    return join "\n", @lines;
}

# First server block serving the root zone (".", ".:53", "dns://.:53"),
# as ($header_line, $closing_brace_line).
sub corefile_root_block {
    my ($lines, $depth) = @_;

    my $from;
    for my $i (0 .. $#$lines) {
        if (!defined $from) {
            next unless $depth->[$i] == 0 && $lines->[$i] =~ /^(.*?)\{\s*$/;
            my $zones = $1;
            next unless grep { m{^(?:[a-z]+://)?\.(?::\d+)?$} } split ' ', $zones;
            $from = $i;
            next;
        }
        return ($from, $i) if $depth->[$i] == 1 && $lines->[$i] =~ /^\s*\}\s*$/;
    }

    return;
}

1;

__END__

=head1 SEE ALSO

L<OCP::Cmd::Apply>, L<OCP::Drift>, L<OCP::Versions>.

=cut
