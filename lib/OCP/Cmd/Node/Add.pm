package OCP::Cmd::Node::Add;
# ABSTRACT: Add an OCPNode CR and optionally reconcile it

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use OCP::Config;
use OCP::Secrets;
use OCP::K8s;
use OCP::Node;
use OCP::Provider;

with 'OCP::Role::Cmd';

option name => (
    is     => 'rw',
    format => 's',
    doc    => 'Node name (may also be given as the first argument)',
);

option role => (
    is      => 'ro',
    format  => 's',
    default => sub { 'worker' },
    doc     => 'Node role (worker|control-plane)',
);

option provider => (
    is     => 'ro',
    format => 's',
    doc    => 'OCPNodeProvider name',
);

option host => (
    is     => 'ro',
    format => 's',
    doc    => 'Host IP or FQDN (ssh provider only)',
);

option server_type => (
    is     => 'ro',
    format => 's',
    doc    => 'Server type override (hetzner only)',
);

option location => (
    is     => 'ro',
    format => 's',
    doc    => 'Location override (hetzner only)',
);

option image => (
    is     => 'ro',
    format => 's',
    doc    => 'Image override (hetzner only)',
);

option gpu => (
    is      => 'ro',
    is_bool => 1,
    doc     => 'Enable GPU support',
);

option no_wait => (
    is      => 'ro',
    is_bool => 1,
    doc     => 'Write CR and exit without waiting for Ready',
);

has k8s => (is => 'rw');

sub _k8s {
    my $self = shift;
    return $self->k8s if $self->k8s;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $kc_content = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc_content;

    my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$kc_fh} $kc_content;
    close $kc_fh;

    my $api = Kubernetes::REST::Kubeconfig->new(
        kubeconfig_path => $kc_fh->filename,
    )->api;

    OCP::K8s->register($api);
    $self->k8s($api);
    return $api;
}

sub _resolve_provider {
    my ($self, $api) = @_;

    my $ns = 'ocp-system';

    if ($self->provider) {
        my $p = eval {
            $api->get('OCPNodeProvider', name => $self->provider, namespace => $ns)
        };
        die "Provider '" . $self->provider . "' not found\n" unless $p;
        return $api->k8s->object_to_struct($p);
    }

    my $list  = $api->list('OCPNodeProvider', namespace => $ns);
    my @items = map { $api->k8s->object_to_struct($_) } @{ $list->items // [] };

    if (@items == 1) {
        return $items[0];
    }

    if (@items == 0) {
        die "No OCPNodeProvider found in cluster. Add one with 'ocp provider add'.\n";
    }

    for my $p (@items) {
        my $ann = $p->{metadata}{annotations} // {};
        return $p if ($ann->{'ocp.internal/default'} // '') eq 'true';
    }

    die "Multiple providers found, --provider required\n";
}

sub _validate_flags {
    my ($self, $provider_type) = @_;

    if ($provider_type eq 'hetzner') {
        die "--host is not valid for provider type 'hetzner'\n"
            if $self->host;
    }
    elsif ($provider_type eq 'ssh') {
        die "--host is required for provider type 'ssh'\n"
            unless $self->host;
        die "--server-type is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->server_type;
        die "--location is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->location;
        die "--image is only valid for provider type 'hetzner' (given for 'ssh')\n"
            if $self->image;
    }
    elsif ($provider_type eq 'local') {
        die "--host is not valid for provider type 'local'\n"
            if $self->host;
        die "--server-type is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->server_type;
        die "--location is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->location;
        die "--image is only valid for provider type 'hetzner' (given for 'local')\n"
            if $self->image;
    }
    else {
        die "Unknown provider type '$provider_type'\n";
    }
}

sub _build_cr {
    my ($self, $provider_name) = @_;

    my %spec = (
        role        => $self->role,
        providerRef => $provider_name,
        ($self->host        ? (host       => $self->host)        : ()),
        ($self->server_type ? (serverType => $self->server_type) : ()),
        ($self->location    ? (location   => $self->location)    : ()),
        ($self->image       ? (image      => $self->image)       : ()),
        ($self->gpu         ? (gpu        => 1)                  : ()),
    );

    return {
        apiVersion => 'ocp.internal/v1',
        kind       => 'OCPNode',
        metadata   => { name => $self->name, namespace => 'ocp-system' },
        spec       => \%spec,
    };
}

sub _robocop_ready {
    my ($self, $api) = @_;

    my $deploy = eval {
        $api->get('Deployment', name => 'robocop', namespace => 'ocp-system')
    };
    return 0 unless $deploy;

    my $h = $api->k8s->object_to_struct($deploy);
    return ($h->{status}{readyReplicas} // 0) >= 1;
}

sub _poll_until_ready {
    my ($self, $api, %opt) = @_;

    my $timeout  = $opt{timeout}  // 600;
    my $interval = $opt{interval} // 5;
    my $deadline = time + $timeout;

    while (time < $deadline) {
        my $cr = eval {
            $api->get('OCPNode', name => $self->name, namespace => 'ocp-system')
        };
        if ($cr) {
            my $h     = $api->k8s->object_to_struct($cr);
            my $phase = $h->{status}{phase} // 'Pending';
            return 1 if $phase eq 'Ready';
            return 0 if $phase eq 'Failed';
        }
        sleep $interval;
    }
    return 0;
}

sub _cli_reconcile {
    my ($self, $cr, $api, $config, $secrets) = @_;

    my $provider_cr = eval {
        $api->get('OCPNodeProvider',
            name      => $cr->{spec}{providerRef},
            namespace => 'ocp-system',
        )
    };
    my $provider_h = $provider_cr
        ? $api->k8s->object_to_struct($provider_cr)
        : undef;

    my $provider_obj = $provider_h
        ? eval { OCP::Provider->from_cr($provider_h, k8s => $api) }
        : undef;

    my $cp_ip = do {
        my $cps = $config->control_planes;
        ($cps && @$cps) ? ($cps->[0]{public_ip} // $cps->[0]{host}) : undef;
    };

    my ($ssh_key, $server_url, $join_token);

    if ($cp_ip) {
        my $ssh_key_path = $config->ssh_private_key_path;
        $ssh_key = do {
            local $/;
            open my $fh, '<', $ssh_key_path
                or die "Cannot read SSH key '$ssh_key_path': $!\n";
            my $k = <$fh>;
            close $fh;
            $k;
        };

        $server_url = $config->join_url($cp_ip);

        my $dist = $config->distribution || 'rke2';
        my $token_path = $dist eq 'k3s'
            ? '/var/lib/rancher/k3s/server/node-token'
            : '/var/lib/rancher/rke2/server/node-token';

        require OCP::SSH;
        my $cp_ssh = OCP::SSH->new(
            host     => $cp_ip,
            key_file => $ssh_key_path,
            user     => 'root',
        );
        my $result = $cp_ssh->run("cat $token_path");
        $join_token = $result->{stdout};
        chomp $join_token if $join_token;
        die "Could not retrieve join token from control plane\n" unless $join_token;
    }

    my $node = OCP::Node->from_cr($cr,
        k8s           => $api,
        ($provider_obj ? (provider => $provider_obj) : ()),
        ($ssh_key      ? (ssh_key  => $ssh_key)      : ()),
        ($server_url   ? (server_url => $server_url) : ()),
        ($join_token   ? (join_token => $join_token) : ()),
        distribution  => ($config->distribution || 'rke2'),
        reconciler_id => 'cli',
    );

    return $node->reconcile_until_ready(timeout => 600);
}

sub execute {
    my ($self, $args, $chain) = @_;

    $self->name($self->name // ($args && $args->[0]));
    die "Usage: ocp node add NAME [--role worker|control-plane]\n"
        unless defined $self->name && length $self->name;

    my $api           = $self->_k8s;
    my $provider_hash = $self->_resolve_provider($api);
    my $provider_type = $provider_hash->{spec}{type}
        or die "Provider has no spec.type\n";
    my $provider_name = $provider_hash->{metadata}{name};

    $self->_validate_flags($provider_type);

    my $cr = $self->_build_cr($provider_name);
    $api->ensure($cr);

    if ($self->no_wait) {
        print $self->name . "\n";
        return 0;
    }

    if ($self->_robocop_ready($api)) {
        sleep 5;
        my $ok = $self->_poll_until_ready($api);
        if ($ok) {
            print "Node '" . $self->name . "' is Ready.\n";
            return 0;
        }
        else {
            print STDERR "Node '" . $self->name . "' did not reach Ready state.\n";
            return 1;
        }
    }

    my $file   = $self->ocp->config;
    my $config = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    my $ok = $self->_cli_reconcile($cr, $api, $config, $secrets);

    if ($ok) {
        print "Node '" . $self->name . "' is Ready.\n";
        return 0;
    }
    else {
        print STDERR "Node '" . $self->name . "' did not reach Ready state.\n";
        return 1;
    }
}

1;

__END__

=head1 NAME

OCP::Cmd::Node::Add - Add an OCPNode CR and optionally reconcile it

=head1 SYNOPSIS

    ocp node add worker-1 --role worker
    ocp node add gpu-1    --role worker --provider hetzner-a --gpu
    ocp node add ssh-1    --role worker --provider ssh-a --host 10.0.0.5
    ocp node add worker-2 --role worker --no-wait

=head1 DESCRIPTION

Creates an OCPNode CR in the C<ocp-system> namespace, then waits for the
node to reach C<Ready> status.  If Robocop is running in the cluster, the
command polls the CR status and lets Robocop do the work.  Otherwise it
drives reconciliation directly via L<OCP::Node>.

Pass C<--no-wait> to write the CR and return immediately.

=head1 SEE ALSO

L<OCP::Node>, L<OCP::Cmd::Node::Rm>, L<OCP::Cmd::Node::Ls>

=cut
