package OCP::Role::Cmd::Machines;
# ABSTRACT: Every machine of a cluster, and their authorized_keys

use File::Temp ();
use Kubernetes::REST::Kubeconfig;

use OCP::Cmd::Apply::Bootstrap ();
use OCP::Cmd::Apply::CR ();
use OCP::K8s;
use OCP::SSH;

use Moo::Role;

requires qw( provider_crs );

# What `ocp keys secure` (k96) and `ocp keys operator add|rm` (k216) share:
# finding every machine of the cluster, and adding a public key to -- or
# removing one from -- root's authorized_keys there over SSH. Written for k96
# in OCP::Cmd::Keys::Secure and moved here unchanged when the operator
# commands needed the same walk over the same machines.

# The cluster API. Injectable for tests, the way OCP::Cmd::Destroy has it;
# otherwise built from kubeconfig.yaml on first use.
has k8s => (is => 'rw');

#
# Machines
#

# Every machine of this cluster that exists, as { name, address, role }: the
# OCPNodes when the cluster can be asked (every role -- status.publicIP, else
# spec.host, the address OCP installed them over), the control planes of
# ocp.yaml with a known address, the recorded one. The OCPNodes go first, so
# their addresses win.
#
# One machine shows up under several sources, and not always under the same
# address: an ssh control plane is a hostname in ocp.yaml and may be an IP in
# its OCPNode. So, as in OCP::Cmd::Destroy, a name (its first label) or an
# address already seen is the same machine.
#
# Second return: ocp.yaml pool hosts with no OCPNode. Not machines yet --
# nothing has joined them -- but they will need the keys when they do.
sub _machines {
    my ( $self, $config, $api ) = @_;

    my ( @machines, %seen );
    my $add = sub {
        my ( $name, $address, $role ) = @_;
        return unless defined $address && length $address && $address ne '-';
        my @ids = ( 'addr:'.lc $address );
        push @ids, 'name:'.lc( (split /\./, $name, 2)[0] ) if defined $name && length $name;
        # A second source for a known machine still teaches its other ids.
        my $known = grep { $seen{$_} } @ids;
        $seen{$_} = 1 for @ids;
        return if $known;
        push @machines, { name => $name // $address, address => $address, role => $role };
    };

    my @nodes = $api ? $self->_ocpnodes($api) : ();
    $add->($_->{metadata}{name}, $_->{status}{publicIP} || $_->{spec}{host},
           $_->{spec}{role} // 'worker') for @nodes;

    my $hetzner = 0;
    for my $cp (@{ $config->control_planes }) {
        my $provider = $cp->{provider} // 'hetzner';
        my $name = $cp->{name}
            // ( $provider eq 'ssh' && $cp->{host}
                 ? (OCP::Cmd::Apply::Bootstrap::host_name_parts($cp->{host}))[0]
                 : $provider eq 'hetzner' ? 'police'.++$hetzner : undef );
        $add->($name, $cp->{host} // $cp->{public_ip}, 'control-plane');
    }
    for my $node (grep { ($_->{role} // 'control-plane') !~ /worker/ } @{ $config->nodes_status }) {
        $add->($node->{name}, $node->{public_ip}, 'control-plane');
    }
    # Its name is made up ("cp-1") when nothing recorded one: the address alone.
    my $status = $config->cluster_status;
    $add->(undef, $status->{public_ip} // $status->{host}, 'control-plane');

    my %named = map { $_->{metadata}{name} => 1 } @nodes;
    my @pending =
        grep { !$named{ $_->{name} } && !$seen{ 'addr:'.lc $_->{host} } }
        map  { { name => $_->{metadata}{name}, host => $_->{spec}{host} } }
        grep { defined $_->{spec}{host} && length $_->{spec}{host} }
        OCP::Cmd::Apply::CR::worker_ocpnodes($config);

    return ( \@machines, \@pending );
}

# Every OCPNode, as plain hashes. A cluster that has a kubeconfig but does not
# answer is not "no workers": the workers would be unknown and skipped. So it
# stops here, before anything was asked or changed; _ocpnodes_unreadable says
# what skipping them would have cost the command at hand.
sub _ocpnodes {
    my ( $self, $api ) = @_;

    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    unless ($list) {
        my $why = $self->_oneline($@ || 'no answer');
        die "ERROR: Could not read the OCPNodes from the cluster API: $why\n"
          . $self->_ocpnodes_unreadable;
    }

    return map { ref $_ eq 'HASH' ? $_ : $api->k8s->object_to_struct($_) }
           @{ $list->items // [] };
}

# The rest of that message; a consumer says what is at stake for it.
sub _ocpnodes_unreadable {
    return "       Without them the workers are unknown. Nothing was changed;\n"
         . "       run the command again once the cluster answers.\n";
}

# The cluster API, or undef when the project has no kubeconfig.yaml (never
# deployed, or deployed and destroyed).
sub _cluster_api {
    my ( $self, $config, $secrets ) = @_;

    return $self->k8s if $self->k8s;
    return undef unless $secrets->has_kubeconfig;

    my $kc = $secrets->read_kubeconfig
        or die "ERROR: kubeconfig.yaml exists but could not be decrypted.\n";

    my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$fh} $kc;
    close $fh;
    # Anchored on the instance: File::Temp unlinks it on destruction.
    $self->{_kc_temp} = $fh;

    my $api = Kubernetes::REST::Kubeconfig->new(kubeconfig_path => $fh->filename)->api;
    OCP::K8s->register($api);
    return $self->k8s($api);
}

# Hetzner is in this project when a control plane, a worker pool or an
# OCPNodeProvider says so.
sub _uses_hetzner {
    my ( $self, $config, $api ) = @_;

    return 1 if grep { ($_->{provider} // 'hetzner') eq 'hetzner' } @{ $config->control_planes };
    return 1 if grep { ($_->{provider} // '') eq 'hetzner' } @{ $config->workers };
    return 0 unless $api;
    return 1 if grep { ($_->{spec}{type} // '') eq 'hetzner' } $self->provider_crs($api);
    return 0;
}

#
# One machine
#

# Appends public keys to root's authorized_keys unless a line already carries
# the key's blob -- the blob, not the line: the same key under another
# comment or behind options is the same key. Each key is [ line, word ], the
# word naming it in the answer ("admin key added"). $key is [ path, label ],
# the key to log in with. Returns what it did, in words.
sub _append_keys {
    my ( $self, $m, $key, @public ) = @_;

    my @adds;
    for my $pk (@public) {
        my ( $line, $word ) = @$pk;
        chomp $line;
        my $blob = $self->_key_blob($line);
        push @adds, 'add '.$self->_sq($line).' '.$self->_sq($blob).' '.$self->_sq($word);
    }

    my $script = join "\n",
        'set -e',
        'umask 077',
        'd=/root/.ssh',
        'f=$d/authorized_keys',
        'mkdir -p "$d"',
        'chmod 700 "$d"',
        'touch "$f"',
        'chmod 600 "$f"',
        # A last line without its newline would swallow the first key added.
        'if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then echo >> "$f"; fi',
        'has() { awk -v b="$1" \'{ for (i = 1; i <= NF; i++) if ($i == b) { f = 1; exit } } END { exit !f }\' "$f"; }',
        'add() { if has "$2"; then echo "$3 key already there"; else printf \'%s\n\' "$1" >> "$f"; echo "$3 key added"; fi; }',
        @adds,
        '';

    my $res = $self->_ssh($m, $key)->run_script($script);
    die $self->_ssh_failure($res) if $res->{exit};

    my @did = grep { /\S/ } split /\n/, ($res->{stdout} // '');
    return @did ? join(', ', @did) : 'keys in place';
}

# Removes every authorized_keys line carrying $blob, logged in with the admin
# key $key ([ path, label ]). Returns how many.
sub _remove_blob {
    my ( $self, $m, $key, $blob ) = @_;

    my $script = join "\n",
        'set -e',
        'umask 077',
        'f=/root/.ssh/authorized_keys',
        'if [ ! -f "$f" ]; then echo 0; exit 0; fi',
        't="$f.ocp-keys"',
        ': > "$t"',
        'n=$(awk -v b='.$self->_sq($blob).' -v out="$t" \'{ m = 0; for (i = 1; i <= NF; i++) if ($i == b) m = 1 } m { c++; next } { print > out } END { print c + 0 }\' "$f")',
        # cat into the file rather than mv over it: owner, mode and any
        # SELinux label stay the ones it had.
        'cat "$t" > "$f"',
        'rm -f "$t"',
        'echo "$n"',
        '';

    my $res = $self->_ssh($m, $key, 'admin')->run_script($script);
    die $self->_ssh_failure($res) if $res->{exit};

    my ($n) = ($res->{stdout} // '') =~ /(\d+)\s*\z/;
    die "unexpected answer: ".$self->_oneline($res->{stdout} // '')."\n" unless defined $n;
    return $n;
}

# Undef when the admin key opens $m, the reason otherwise.
sub _admin_refused {
    my ( $self, $m, $key ) = @_;

    my $res = eval { $self->_ssh($m, $key, 'admin')->run('true') };
    return $self->_oneline($@) unless $res;
    return undef unless $res->{exit};
    return $self->_ssh_failure($res);
}

# $key is [ path, label ]; $purpose names the admin key to OCP::SSH, so a
# refusal says which key is missing (k209). The bootstrap key has none.
sub _ssh {
    my ( $self, $m, $key, $purpose ) = @_;
    my ( $path, $label ) = @$key;
    return OCP::SSH->new(
        host      => $m->{address},
        user      => 'root',
        key_file  => $path,
        key_label => $label,
        ($purpose ? (key_purpose => $purpose) : ()),
    );
}

#
# Helpers
#

sub _machine_label {
    my ( $self, $m ) = @_;
    return $m->{name} eq $m->{address} ? $m->{name} : $m->{name}.' ('.$m->{address}.')';
}

# The base64 body of an authorized_keys line: what identifies the key, with
# the type in front and the comment after it left out.
sub _key_blob {
    my ( $self, $line ) = @_;
    my ($blob) = $line =~ m{\A\s*\S+\s+([A-Za-z0-9+/]+=*)(?:\s|\z)};
    die "Not an SSH public key: ".$self->_oneline($line)."\n" unless defined $blob;
    return $blob;
}

sub _sq {
    my ( $self, $s ) = @_;
    $s =~ s/'/'\\''/g;
    return "'".$s."'";
}

sub _ssh_failure {
    my ( $self, $res ) = @_;
    my $why = $res->{stderr} // '';
    $why = $res->{stdout} // '' unless $why =~ /\S/;
    $why = 'ssh exited with '.($res->{exit} // '?') unless $why =~ /\S/;
    return $self->_oneline($why);
}

sub _oneline {
    my ( $self, $s ) = @_;
    $s = '' unless defined $s;
    $s =~ s/ at \S+ line \d+\.?\s*\z//;
    $s =~ s/\s+/ /g;
    $s =~ s/\A\s+|\s+\z//g;
    return $s;
}

1;

__END__

=head1 NAME

OCP::Role::Cmd::Machines - Every machine of a cluster, and their authorized_keys

=head1 SYNOPSIS

    package OCP::Cmd::Keys::Something;
    use Moo;
    with 'OCP::Role::Cmd', 'OCP::Role::Cmd::Machines';

    my $api = $self->_cluster_api($config, $secrets);
    my ($machines, $pending) = $self->_machines($config, $api);
    for my $m (@$machines) {
        $self->_append_keys($m, [ $key->path, $key->label ], [ $public, 'operator' ]);
    }

=head1 DESCRIPTION

What L<OCP::Cmd::Keys::Secure> (k96) and the operator commands
L<OCP::Cmd::Keys::Operator::Add> and L<OCP::Cmd::Keys::Operator::Rm> (k216)
share.

C<_machines> lists every machine of the cluster as C<< { name, address, role } >>:
each OCPNode in C<ocp-system> when the cluster can be asked (at
C<status.publicIP>, else C<spec.host>), plus the control planes of
F<ocp.yaml> and the recorded one, deduplicated by name or address. Its second
return are the F<ocp.yaml> pool hosts that have no OCPNode yet. A kubeconfig
whose cluster does not answer dies before anything is changed;
C<_ocpnodes_unreadable> is the consumer's say in that message.

C<_append_keys> appends public keys to F</root/.ssh/authorized_keys> unless
their blob is already there; C<_remove_blob> removes every line carrying a
blob, logged in with the admin key, keeping owner, mode and the other lines;
C<_admin_refused> tries the admin key alone. They speak to the machine through
L<OCP::SSH>.

The consumer also consumes L<OCP::Role::Cmd>. The C<k8s> attribute takes an
API handle (tests); otherwise C<_cluster_api> builds one from
F<kubeconfig.yaml>.

=cut
