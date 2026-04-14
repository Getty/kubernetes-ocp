package OCP::Node;
# ABSTRACT: Trigger-neutral node reconcile state machine

use Moo;
use Time::Piece ();
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
        path        => "/apis/ocp.internal/v1/namespaces/$ns/ocpnodes/$name/status",
        body        => { status => \%updates },
        contentType => 'application/merge-patch+json',
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

1;
