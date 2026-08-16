package OCP::Provider::Hetzner;
# ABSTRACT: Hetzner Cloud infrastructure provider

use Moo;
use WWW::Hetzner::Cloud;

=attr token

    my $hz = OCP::Provider::Hetzner->new(token => $ENV{HETZNER_API_TOKEN});

Hetzner Cloud API token. Required, no default. Used to build the
L<WWW::Hetzner::Cloud> client lazily on first call.

=attr cluster_name

    my $hz = OCP::Provider::Hetzner->new(cluster_name => 'mycluster');

The OCP cluster this provider instance manages. Embedded as the
C<ocp-cluster> label on every server created or looked up. Optional:
servers can be created without a cluster scope, but C<server_exists>
and C<list_servers_by_cluster> then have nothing to filter by.

=attr ssh_key_name

    my $hz = OCP::Provider::Hetzner->new(ssh_key_name => 'ocp-mycluster-admin');

Name of an SSH key already uploaded to the Hetzner project (see
C<upload_ssh_key>). C<create_server> falls back to it when the caller passes
no C<ssh_keys> of its own — which is exactly the worker path: L<OCP::Node>
is trigger-neutral, so neither it nor robocop knows the cluster name the key
is derived from. L<OCP::Provider/from_cr> fills this in from
C<spec.hetzner.sshKeyName> on the OCPNodeProvider CR.

Empty by default, and an empty value is not a usable one: a server with no
key is unreachable, so C<create_server> refuses instead of creating it.

=attr default_server_type

    my $hz = OCP::Provider::Hetzner->new(default_server_type => 'cx42');

The server type a node created through this provider gets when its own
OCPNode spec names none.  Third of the four ranks C<create_server> resolves
(see there); L<OCP::Provider/from_cr> fills it from
C<spec.hetzner.serverType> on the OCPNodeProvider CR.  Empty by default, and
empty counts as absent.

=attr default_image

    my $hz = OCP::Provider::Hetzner->new(default_image => 'debian-12');

The OS image, same rank and same shape, from C<spec.hetzner.image>.

=attr default_location

    my $hz = OCP::Provider::Hetzner->new(default_location => 'nbg1');

The datacentre location, same rank and same shape, from
C<spec.hetzner.location>.  This is the one that makes a provider named
C<hetzner-nbg1> worth having: every node of it that does not pick a region
lands in that region.

=cut

has token => (is => 'ro', required => 1);
has cluster_name => (is => 'ro', default => '');
has ssh_key_name => (is => 'ro', default => '');

has default_server_type => (is => 'ro', default => '');
has default_image       => (is => 'ro', default => '');
has default_location    => (is => 'ro', default => '');

has cloud => (
    is      => 'lazy',
    builder => sub { WWW::Hetzner::Cloud->new(token => shift->token) },
);

=method upload_ssh_key

    $prov->upload_ssh_key('ocp-mycluster-admin', $pubkey);

Idempotently uploads a public key to the Hetzner project so it can be
referenced by C<server->ssh_keys> when a server is created. Dies when
the key name is empty or the public key is missing.

=cut

sub upload_ssh_key {
    my ($self, $key_name, $pubkey) = @_;

    die "SSH public key is empty or undefined\n" unless $pubkey && $pubkey =~ /\S/;
    die "SSH key name is required\n" unless $key_name;

    $self->cloud->ssh_keys->ensure($key_name, $pubkey);
}

=method server_exists

    my $server = $prov->server_exists($node_name);

Looks up an existing server by the C<ocp-cluster>/C<ocp-node> label pair.
Returns the L<WWW::Hetzner::Cloud::Server> object when one matches;
C<undef> otherwise. Used by C<create_server> to keep provisioning
idempotent: a node that already has a labelled server is reported as
"found", not "created".

=cut

sub server_exists {
    my ($self, $node_name) = @_;

    my $cluster = $self->cluster_name;
    return unless $cluster;

    my $servers = $self->cloud->servers->list_by_label(
        "ocp-cluster=$cluster,ocp-node=$node_name"
    );

    return $servers->[0] if @$servers;
    return;
}

=method create_server

    my $info = $prov->create_server(
        name        => 'police1',
        node        => 'police1',
        role        => 'control-plane',
        server_type => 'cx32',
        image       => 'debian-13',
        location    => 'fsn1',
        ssh_keys    => ['ocp-mycluster-admin'],
    );

Returns a hashref with the keys callers read:

=over 4

=item C<id>

Hetzner server id (integer). C<undef> when the server came from
C<server_exists> and therefore has no fresh handle (callers fall back to
C<existing->id> in that case).

=item C<ip>

Public IPv4. C<undef> immediately after creation — the server is not
running yet, and the IP is not allocated. Call C<wait_for_running> to fill
it in.

=item C<newly_created>

Boolean. C<0> when the server was matched by label, C<1> after a fresh
C<servers->create>. The control-plane flow uses it to decide whether to
wait and whether to clean up on failure.

=back

Idempotency: when C<cluster_name> is set, C<server_exists> runs first.
A label match is returned with C<newly_created = 0> and no IP set; this
is the same shape the caller would have built from a fresh create, minus
the wait.

C<server_type>, C<image> and C<location> have four possible sources, and the
order between them is the contract:

=over 4

=item 1. the named option

C<< server_type => 'cx32' >>. The bootstrap path
(L<OCP::Cmd::Apply::Bootstrap>) names all three, so nothing below can move
the control plane.

=item 2. the OCPNode spec

C<< spec => $cr->{spec} >>, which is all L<OCP::Node/_provision> passes —
C<spec.serverType>, C<spec.image>, C<spec.location>, what the user typed into
C<ocp node add>. Note the spelling: camelCase in the CR, snake_case in the
options.

=item 3. this provider's defaults

L</default_server_type>, L</default_image>, L</default_location>, filled by
L<OCP::Provider/from_cr> from C<spec.hetzner.*> on the OCPNodeProvider CR.
The per-provider rank: what every node of C<hetzner-nbg1> gets unless it says
otherwise.

=item 4. the code default

C<cx32> / C<debian-13> / C<fsn1>. The last word, and the only one that is not
configurable.

=back

Higher wins, and an empty string counts as absent at every rank — a
C<serverType: ""> in a hand-edited CR is a node that did not choose, not a
node that chose nothing.

C<ssh_keys> resolves on its own two-rank scale: the argument, then
L</ssh_key_name>. When neither yields a key the call dies before anything is
created, because a Hetzner server with an empty C<authorized_keys> runs,
bills, and can never be logged in to.

=cut

# First value that is present and non-empty. The empty string is treated as
# absent on purpose: `ocp node add` writes spec fields only when they were
# given, but a hand-edited CR can carry `serverType: ""`, and that must not
# beat the default.
sub _first_set {
    for my $value (@_) {
        return $value if defined $value && length $value;
    }
    return undef;
}

sub create_server {
    my ($self, %opts) = @_;

    my $name      = $opts{name} or die "Server name required\n";
    my $node_name = $opts{node} // $name;
    my $cluster   = $opts{cluster} // $self->cluster_name;

    # Idempotency: check if server already exists with matching labels
    if ($cluster) {
        my $existing = $self->server_exists($node_name);
        if ($existing) {
            return {
                id           => $existing->id,
                ip           => $existing->ipv4,
                newly_created => 0,
            };
        }
    }

    # OCP::Node::_provision passes the OCPNode spec rather than these options,
    # so reading only the options silently threw away every serverType,
    # location and image a user typed into `ocp node add`. Same defect and
    # same fix as OCP::Provider::SSH::resolve_host (karr #51, #92).
    my $spec = ref $opts{spec} eq 'HASH' ? $opts{spec} : {};

    # An explicitly passed key wins, then the cluster key this provider was
    # built with. An empty list is never a default: the machine would be
    # unreachable from its first boot, which is not a state any caller wants
    # and not one that can be repaired afterwards.
    my @ssh_keys = grep { defined && length } @{ $opts{ssh_keys} // [] };
    @ssh_keys = ($self->ssh_key_name)
        if !@ssh_keys && length $self->ssh_key_name;

    die "Refusing to create Hetzner server '$name' without an SSH key: it "
      . "would run, cost money and be unreachable.\n"
      . "Pass ssh_keys => [...], or set spec.hetzner.sshKeyName on the "
      . "OCPNodeProvider CR ('ocp apply' writes it as ocp-<cluster>-admin).\n"
        unless @ssh_keys;

    # The order in each _first_set below IS the contract, so read it as one:
    # named option, then the node's own spec, then this provider's default,
    # then the constant. Rank 3 is the one karr #100 added -- the provider CR
    # carried these three fields from the beginning, `ocp provider add` wrote
    # them and `ocp provider ls` printed them, and nothing read them, so
    # `--location nbg1` moved no server.
    #
    # It sits BELOW the node spec because the node is the more specific
    # statement, and ABOVE the constant because a provider the user configured
    # has to beat a value hardcoded here. That the OCPNodeProvider CRD declares
    # no `default:` on these three is what keeps the rank meaningful: a
    # materialised schema default is indistinguishable from a chosen value, so
    # it would make "this provider said nothing" unrepresentable and the
    # constant unreachable.
    my $server = $self->cloud->servers->create(
        name        => $name,
        server_type => _first_set($opts{server_type}, $spec->{serverType},
                                  $self->default_server_type, 'cx32'),
        image       => _first_set($opts{image},       $spec->{image},
                                  $self->default_image,       'debian-13'),
        location    => _first_set($opts{location},    $spec->{location},
                                  $self->default_location,    'fsn1'),
        ssh_keys    => \@ssh_keys,
        labels      => {
            'ocp-cluster' => $cluster,
            'ocp-role'    => $opts{role} // 'control-plane',
            'ocp-node'    => $node_name,
        },
    );

    return {
        id            => $server->id,
        ip            => undef,  # not yet available, need wait_for_running
        newly_created => 1,
        _server       => $server,
    };
}

=method wait_for_running

    $prov->wait_for_running($info);

Blocks until the server reported in C<$info> is in C<running> state, then
mutates C<$info> in place to set C<ip> to the public IPv4 and returns it.
C<$timeout> defaults to C<$OCP::Provider::Hetzner::ADDRESS_TIMEOUT>
(120 s), and a server that does not get there in time makes this die rather
than return an C<$info> with no C<ip>.

Only C<id> is read out of C<$info>, so a caller that holds nothing but the
server id can build one: C<< { id => $id } >>.

Both paths call this. L<OCP::Cmd::Apply::Bootstrap> calls it right after
C<create_server> for the control plane, and L<OCP::Node/_resolve_host>
calls it for a worker whose C<status.publicIP> is still empty. The line
that used to stand here — "robocop never does, its node has the IP
already" — was the assumption behind karr #99: a worker created through an
OCPNode CR has no address at all until this method has run, and the install
failed with "No host IP" before it ever tried to connect.

=cut

# How long a freshly created Hetzner server may take to reach C<running>.
# Both L<OCP::Cmd::Apply::Bootstrap> and L<OCP::Node/_resolve_host> spend this
# budget on the same wait; neither names its own number, so a region that is
# slow enough to make `ocp apply` sit there is fast enough for a worker to give
# up. The number lives in the module that owns the wait -- the same shape
# L<OCP::SSH::WAIT_TIMEOUT> uses for the SSH equivalent (karr #109). `our` so
# a test can shorten it without timing the real thing.
our $ADDRESS_TIMEOUT = 120;

sub wait_for_running {
    my ($self, $server_info, $timeout) = @_;
    $timeout //= $ADDRESS_TIMEOUT;

    my $server = $self->cloud->servers->wait_for_status(
        $server_info->{id}, 'running', $timeout
    );

    $server_info->{ip} = $server->ipv4;
    return $server_info;
}

=method get_server_ip

    my $ip = $prov->get_server_ip($server_id);

Reads the current IPv4 of a known server id. Used by callers that hold
the id but not the C<$info> hashref.

=cut

sub get_server_ip {
    my ($self, $server_id) = @_;
    my $server = $self->cloud->servers->get($server_id);
    return $server->ipv4;
}

=method delete_server

    $prov->delete_server($server_id, name => 'w1', host => '1.2.3.4');

Deletes the Hetzner server with the given id. C<$server_id> is the only
load-bearing argument; C<name> and C<host> are accepted because
L<OCP::Node/teardown> passes them through but are not used here. A
C<delete_server(undef)> is a no-op — empty ids never call the API, so a
teardown on an already-gone node does not cost a round trip.

=cut

sub delete_server {
    my ($self, $server_id, %opts) = @_;
    return unless defined $server_id && length $server_id;
    $self->cloud->servers->delete($server_id);
}

=method cleanup_on_failure

    eval { $prov->cleanup_on_failure($server_id) };

Best-effort C<delete_server> for a server that just failed to provision.
A failure here is downgraded to a warning so the original error is not
masked.

=cut

sub cleanup_on_failure {
    my ($self, $server_id) = @_;
    return unless $server_id;
    eval { $self->delete_server($server_id) };
    warn "Cleanup failed for server $server_id: $@\n" if $@;
}

=method list_servers_by_cluster

    my @servers = @{ $prov->list_servers_by_cluster('mycluster') };

Returns every server carrying the C<ocp-cluster=$cluster> label. Used by
C<ocp destroy> to find orphans that C<.ocp/status.yaml> did not record
(servers that ran but never reported back).

=cut

sub list_servers_by_cluster {
    my ($self, $cluster_name) = @_;
    $cluster_name //= $self->cluster_name;
    return $self->cloud->servers->list_by_label("ocp-cluster=$cluster_name");
}

1;

__END__

=synopsis

    use OCP::Provider::Hetzner;

    my $prov = OCP::Provider::Hetzner->new(
        token        => $ENV{HETZNER_API_TOKEN},
        cluster_name => 'mycluster',
    );

    $prov->upload_ssh_key('ocp-mycluster-admin', $pubkey);
    my $info = $prov->create_server(
        name     => 'police1',
        node     => 'police1',
        role     => 'control-plane',
        location => 'fsn1',
    );
    $prov->wait_for_running($info);
    print "Server up at $info->{ip}\n";

=description

Manages server lifecycle on Hetzner Cloud. The methods on this class are
the in-cluster adapter side of L<OCP::Provider>'s seam — C<ocp apply> and
robocop reach them through L<OCP::Provider::Hetzner> only.

Every server this adapter creates gets an SSH key, or it does not get
created. C<create_server> takes the key from its C<ssh_keys> argument (the
bootstrap path) or from C<ssh_key_name> (the worker path, filled from the
OCPNodeProvider CR), and refuses when both are empty — an unreachable
Hetzner server cannot be repaired after the fact, only deleted and paid for.

Idempotency is built in: C<create_server> checks the
C<ocp-cluster>/C<ocp-node> label pair before allocating anything, so a
node whose server already exists is reported as C<newly_created = 0>
with the same hash shape a fresh create would have produced. The control
plane path therefore calls C<wait_for_running> only on the freshly
created branch.

=method cluster_name

The OCP cluster this provider manages, embedded as the C<ocp-cluster>
label. Set by the factory from C<OCP::Provider/for_spec>'s
C<cluster_name> arg or C<OCP::Provider/from_cr>'s
C<spec.clusterName> — B<not> the CR's own name, which is C<< <type>-default >>
and labelled every worker into a cluster C<ocp destroy> could not find
(karr #98).

=seealso

L<OCP::Provider>, L<OCP::Role::Provider::ExistingHost>,
L<WWW::Hetzner::Cloud>

=cut