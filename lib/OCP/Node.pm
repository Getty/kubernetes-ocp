package OCP::Node;
# ABSTRACT: Trigger-neutral node reconcile state machine

use Moo;
use File::Temp ();
use Time::Piece ();
use OCP::Versions;
use namespace::clean;

our $VERSION = '0.001';

has cr            => (is => 'ro', writer => '_set_cr', required => 1);
has k8s           => (is => 'ro', required => 1);
has provider      => (is => 'ro');
has ssh_key       => (is => 'ro');
has server_url    => (is => 'ro');
has join_token    => (is => 'ro');
has distribution  => (is => 'ro', default => sub { 'rke2' });
has registry_cfg  => (is => 'ro');
has verbose       => (is => 'ro', default => 0);
has reconciler_id => (is => 'ro', default => sub { 'cli' });
has ssh_class     => (is => 'ro', default => sub { 'OCP::SSH' });
has rex_class     => (is => 'ro', default => sub { 'OCP::Rex' });

has _ssh_key_file => (is => 'lazy', builder => '_build_ssh_key_file');

sub _build_ssh_key_file {
    my ($self) = @_;
    my $tmp = File::Temp->new(SUFFIX => '.key', UNLINK => 1);
    print $tmp $self->ssh_key;
    close $tmp;
    chmod 0600, $tmp->filename;
    return $tmp;
}

sub name      { $_[0]->cr->{metadata}{name} }
sub role      { $_[0]->cr->{spec}{role} }
sub phase     { $_[0]->cr->{status}{phase} // 'Pending' }
sub namespace { $_[0]->cr->{metadata}{namespace} // 'ocp-system' }

sub from_cr {
    my ($class, $cr, %deps) = @_;
    return $class->new(cr => $cr, %deps);
}

sub _rfc3339_now { Time::Piece::gmtime->strftime('%Y-%m-%dT%H:%M:%SZ') }

sub _lease_parse {
    my $v = shift;
    return unless $v;
    $v =~ /^([^@]+)\@([^@]+)\@(\d+)$/ or return;
    return { holder => $1, ts => $2, ttl => $3 };
}

sub _lease_live {
    my $l = _lease_parse(shift);
    return 0 unless $l;
    my $t = Time::Piece->strptime($l->{ts}, '%Y-%m-%dT%H:%M:%SZ')->epoch;
    return (time - $t) < $l->{ttl};
}

sub _lease_mine {
    my ($v, $id) = @_;
    my $l = _lease_parse($v);
    return 0 unless $l;
    return $l->{holder} eq $id;
}

sub _api_version { 'ocp.internal/v1' }
sub _kind        { 'OCPNode' }

sub _acquire_lease {
    my $self = shift;
    my $cr = $self->k8s->get($self->_api_version, $self->_kind, $self->name,
                             namespace => $self->namespace);
    $cr ||= $self->cr;
    my $ann = $cr->{metadata}{annotations} //= {};
    my $existing = $ann->{'ocp.internal/reconciler-lease'};
    if ($existing && _lease_live($existing) && !_lease_mine($existing, $self->reconciler_id)) {
        die "lease held by another reconciler: $existing\n";
    }
    $ann->{'ocp.internal/reconciler-lease'} = sprintf "%s@%s@%d",
        $self->reconciler_id, _rfc3339_now(), 300;
    my $updated = $self->k8s->update($cr);
    $self->_set_cr($updated) if $updated;
    return $updated;
}

sub _release_lease {
    my $self = shift;
    my $cr = $self->cr;
    my $ann = $cr->{metadata}{annotations} // {};
    return unless exists $ann->{'ocp.internal/reconciler-lease'};
    delete $ann->{'ocp.internal/reconciler-lease'};
    my $updated = $self->k8s->update($cr);
    $self->_set_cr($updated) if $updated;
    return $updated;
}

sub _patch_status {
    my ($self, %updates) = @_;
    $updates{lastReconcileTime} //= _rfc3339_now();
    $updates{reconciler}        //= $self->reconciler_id;

    my $status = $self->cr->{status} //= {};
    $status->{$_} = $updates{$_} for keys %updates;

    my $name = $self->name;
    my $ns   = $self->namespace;

    return $self->k8s->patch(
        'OCPNode',
        name      => $name,
        namespace => $ns,
        patch     => { status => \%updates },
        type      => 'merge',
    );
}

sub _provision {
    my $self = shift;

    die "cannot provision: phase is not Pending (got: " . $self->phase . ")\n"
        unless $self->phase eq 'Pending';

    $self->_acquire_lease;

    my $result = $self->provider->create_server(
        name => $self->name,
        node => $self->name,
        role => $self->role,
        spec => $self->cr->{spec},
    );

    $self->_patch_status(
        phase      => 'Installing',
        providerId => $result->{id},
        publicIP   => $result->{ip} // $result->{ipv4},
        message    => 'Server provisioned, installing Kubernetes',
    );

    $self->_release_lease;

    return $result;
}

sub _install_kubernetes {
    my $self = shift;

    my $name = $self->name;
    my $host = $self->cr->{status}{publicIP} || $self->cr->{spec}{host};
    my $role = $self->role;

    unless ($host) {
        $self->_patch_status(phase => 'Failed', message => 'No host IP in status or spec');
        return;
    }

    my $ssh = $self->ssh_class->new(
        host     => $host,
        key_file => $self->_ssh_key_file->filename,
        user     => 'root',
    );
    eval { $ssh->wait_for_ssh(60) };
    if ($@) {
        $self->_patch_status(phase => 'Failed', message => "SSH not reachable: $@");
        return;
    }

    my $rex = $self->rex_class->new(
        host     => $host,
        key_file => $self->_ssh_key_file->filename,
        user     => 'root',
        verbose  => $self->verbose,
    );

    my $rke2_version = OCP::Versions->get_component_version('rke2');

    my $task = $self->distribution eq 'k3s'
        ? 'install_k3s_agent'
        : 'install_rke2_agent';

    my %params = (
        server    => $self->server_url,
        token     => $self->join_token,
        version   => $rke2_version,
        node_name => $name,
        hostname  => $name,
        ntp       => 1,
    );

    my $ok = eval { $rex->run_task($task, %params) };
    if (!$ok || $@) {
        $self->_patch_status(phase => 'Failed',
            message => "Rex task failed: " . ($@ // 'unknown'));
        return;
    }

    $self->_patch_status(phase => 'Joining',
        message => 'RKE2 agent installed, waiting for node registration');
}

sub _wait_ready {
    my $self = shift;

    my $name     = $self->name;
    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $name;

    my $k8s_node = eval {
        $self->k8s->get('Node', name => $k8s_name);
    };

    return 0 unless $k8s_node;

    my $ready = 0;
    for my $cond (@{ $k8s_node->{status}{conditions} // [] }) {
        if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
            $ready = 1;
            last;
        }
    }

    if ($ready) {
        $self->_patch_status(
            phase              => 'Ready',
            kubernetesNodeName => $k8s_name,
            joinedAt           => _rfc3339_now(),
            message            => 'Node joined and Ready',
        );
    }

    return $ready;
}

sub reconcile {
    my $self = shift;
    my $p = $self->phase;

    return 0 if $p eq 'Failed' || $p eq 'Terminating';

    eval {
        if    ($p eq 'Pending')      { $self->_provision }
        elsif ($p eq 'Provisioning') { $self->_install_kubernetes }
        elsif ($p eq 'Installing')   { $self->_wait_ready }
        elsif ($p eq 'Joining')      { $self->_wait_ready }
        elsif ($p eq 'Ready')        { $self->_verify }
        else                         { die "unknown phase: $p\n" }
    };
    if ($@) {
        $self->_patch_status(phase => 'Failed', message => "$@");
        return 0;
    }
    return 1;
}

sub _refresh {
    my $self = shift;
    my $fresh = $self->k8s->get($self->_api_version, $self->_kind, $self->name,
                                namespace => $self->namespace);
    $self->_set_cr($fresh) if $fresh;
}

sub reconcile_until_ready {
    my ($self, %opt) = @_;
    my $timeout  = $opt{timeout}  // 600;
    my $interval = $opt{interval} // 5;
    my $deadline = time + $timeout;

    while (time < $deadline) {
        $self->_refresh;
        return 1 if $self->phase eq 'Ready';
        return 0 if $self->phase eq 'Failed';
        $self->reconcile;
        sleep $interval;
    }
    return 0;
}

sub teardown {
    my $self = shift;
    $self->_patch_status(phase => 'Terminating', message => 'Teardown initiated');

    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $self->name;
    eval {
        $self->k8s->patch(
            'Node',
            name  => $k8s_name,
            patch => { spec => { unschedulable => \1 } },
        );
    };

    if ($self->provider) {
        eval { $self->provider->delete_server(name => $self->name) };
    }

    eval {
        $self->k8s->delete('v1', 'Node', $k8s_name);
    };

    eval {
        $self->k8s->delete($self->_api_version, $self->_kind, $self->name,
                           namespace => $self->namespace);
    };

    return 1;
}

sub _verify {
    my $self = shift;

    my $name     = $self->name;
    my $k8s_name = $self->cr->{status}{kubernetesNodeName} // $name;

    my $k8s_node = eval {
        $self->k8s->get('Node', name => $k8s_name);
    };

    return 0 unless $k8s_node;

    for my $cond (@{ $k8s_node->{status}{conditions} // [] }) {
        if ($cond->{type} eq 'Ready' && $cond->{status} eq 'True') {
            return 1;
        }
    }

    return 0;
}

1;
