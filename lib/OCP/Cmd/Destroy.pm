package OCP::Cmd::Destroy;
# ABSTRACT: Destroy cluster

use Moo;
use MooX::Cmd;
use MooX::Options;
use File::Temp ();
use Kubernetes::REST::Kubeconfig;
use Path::Tiny qw(path);

use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::K8s;
use OCP::Provider;
use OCP::Secrets;

with 'OCP::Role::Cmd';
with 'OCP::Role::Cmd::Confirm';

option force => (
    is    => 'ro',
    short => 'f',
    doc   => 'Skip confirmation',
);

option keep_status => (
    is  => 'ro',
    doc => 'Keep the local cluster state (.ocp/status.yaml, .ocp/deployed.yaml)',
);

# The cluster API. Built from the encrypted kubeconfig on first use; tests
# hand in a double.
has k8s => (is => 'rw');

# Set once the API failed to answer, so the teardown does not wait out a
# second timeout on it.
has _api_down => (is => 'rw');

# The OCPNodeProvider CRs as _ocpnode_entries read them, by name.
has _provider_crs => (is => 'rw', default => sub { {} });

# The Hetzner adapters built from those CRs, by CR name, and why a CR gave
# none (k181). Filled while the API answers, before anything is deleted.
has _cr_hetzner       => (is => 'ro', default => sub { {} });
has _cr_hetzner_error => (is => 'ro', default => sub { {} });

# The adapter built from the local token, if there is one.
has _local_hetzner => (is => 'rw');

# Servers this project paid for but which are not labelled with its name.
#
# Until k98, OCP::Provider::from_cr took the provider CR's OWN name for
# the cluster name, and `ocp apply` writes that CR as "<type>-default". So
# every worker brought up by `ocp node add` or robocop was labelled
# ocp-cluster=hetzner-default while the control plane carried the real cluster
# name. The teardown above searches ocp-cluster=<cluster> and walks straight
# past them — they keep running, keep billing, and this command still says
# "Cluster destroyed."
#
# The fix stops new ones appearing; it cannot relabel the machines already out
# there. So they get NAMED, never deleted. That label is generic by
# construction: a match may belong to a different OCP cluster in the same
# Hetzner project with the same defect, and deleting someone else's control
# plane to tidy up a labelling bug would be worse than the bug.
sub _report_mislabelled_servers {
    my ($self, $config, $hetzner_prov) = @_;
    return unless $hetzner_prov;

    # Exactly the names OCP::Cmd::Apply::CR::ensure_provider_cr writes, so this
    # is a derivation and not a guess. A provider added by hand under some
    # other name is out of reach here — the selector printed below finds those.
    my %stale;
    for my $entry (@{$config->control_planes}, @{$config->workers}) {
        my $type = $entry->{provider} // 'hetzner';
        next unless $type eq 'hetzner';
        my $label = "$type-default";
        next if $label eq $config->name;   # then the label was right all along
        $stale{$label} = 1;
    }
    return unless %stale;

    for my $label (sort keys %stale) {
        my $servers = eval { $hetzner_prov->list_servers_by_cluster($label) } || [];
        next unless @$servers;

        print STDERR "\n";
        printf STDERR "[!!] %d Hetzner server(s) carry the label ocp-cluster=%s and were\n",
               scalar @$servers, $label;
        print  STDERR "     NOT deleted. They are this cluster's, mislabelled before the\n";
        print  STDERR "     fix for k98 — they keep running and keep billing.\n";
        for my $s (@$servers) {
            printf STDERR "       - %s (id %s, %s)\n",
                   eval { $s->name } // '?',
                   eval { $s->id }   // '?',
                   eval { $s->ipv4 } // '-';
        }
        print  STDERR "     They are not removed automatically: that label is generic, so a\n";
        print  STDERR "     match can belong to another cluster in the same project. Check\n";
        print  STDERR "     and delete by hand:\n";
        print  STDERR "       hcloud server list -l ocp-cluster=$label\n";
        print  STDERR "       hcloud server delete <name>\n";
    }
}

# The cluster API, or undef when there is none to ask. Nothing here may die:
# a teardown has to run on a project whose kubeconfig is already gone, whose
# age key is missing, or whose control plane is half down -- that is when
# people run it. Whether the API really answers is only known at the first
# call; _ocpnode_entries makes that call and says so when it fails.
sub _cluster_api {
    my ($self, $config) = @_;
    return $self->k8s if $self->k8s;

    my $api = eval {
        my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
        my $kc      = $secrets->read_kubeconfig or return;

        my $kc_fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
        print {$kc_fh} $kc;
        close $kc_fh;
        # Anchored on the instance: File::Temp unlinks on destruction.
        $self->{_kc_temp} = $kc_fh;

        my $api = Kubernetes::REST::Kubeconfig->new(
            kubeconfig_path => $kc_fh->filename,
        )->api;
        OCP::K8s->register($api);
        $api;
    };
    return $self->k8s($api) if $api;
    return;
}

# Every machine this cluster has, one entry each, workers first (k177).
#
# status.yaml records the control planes -- nothing else. Workers robocop
# brought up exist only as OCPNodes, so while the API answers those are read
# as the source of truth; the Hetzner label search and the ocp.yaml worker
# pools are merged in on every run, not only when status.yaml is empty, so a
# worker is still found when the API is already gone. The control-plane
# guess from ocp.yaml stays a last resort: its names are made up
# ("<cluster>-cp-N") and would never match a recorded node.
#
# Workers go first because a control plane torn down first takes the API --
# and with it the only record of the workers -- along.
sub _collect_nodes {
    my ($self, $config, $hetzner_prov, $api) = @_;

    my (@nodes, %by_key);
    my $add = sub {
        my ($node, @aliases) = @_;
        my @keys = $self->_node_keys($node, @aliases);
        my ($have) = grep { defined } @by_key{@keys};
        if ($have) {
            # The same machine from a second source: fill in what the first
            # did not know (a role, a providerId), never overwrite it.
            $have->{$_} //= $node->{$_} for keys %$node;
            $by_key{$_} = $have for @keys;
            return 0;
        }
        push @nodes, $node;
        $by_key{$_} = $node for @keys;
        return 1;
    };

    $add->({ %$_ }) for @{ $config->nodes_status };

    $add->(@$_) for $self->_ocpnode_entries($api);

    # The tokens the provider CRs hold, read now: the API goes with the
    # control planes (k181).
    $self->_build_cr_hetzner($config, $api);

    # Hetzner servers carrying this cluster's label that no other source knew
    # -- searched under every distinct token, since a provider CR can point at
    # another Hetzner project than the local token does. A find remembers the
    # CR whose token found it, so the same token deletes it. Whether a search
    # answered, and why one did not, is kept for the control-plane fallback
    # below (k345).
    my ($announced, $searched, $search_error);
    for my $source ($self->_hetzner_sources($hetzner_prov)) {
        my ($ref, $prov) = @$source;
        my $servers = eval { $prov->list_servers_by_cluster($config->name) || [] };
        unless ($servers) {
            $search_error //= $@;
            next;
        }
        $searched++;
        for my $s (@$servers) {
            my $new = $add->({
                name       => $s->name,
                provider   => 'hetzner',
                providerId => $s->id,
                public_ip  => $s->ipv4 // '-',
                (defined $ref ? (provider_ref => $ref) : ()),
            });
            next unless $new;
            print "Found orphaned servers at Hetzner (not in status):\n"
                unless $announced++;
            print '  - '.$s->name."\n";
        }
    }

    $add->(@$_) for $self->_spec_worker_entries($config);

    # Last resort: the control planes as ocp.yaml describes them.
    #
    # The gate uses OCP::Provider->known_type rather than `eq 'ssh'`, so a
    # CP carrying `provider: local` reaches the destroy loop instead of being
    # dropped on the floor -- the same seam k103 found in six other input
    # checks. An unknown provider is skipped rather than relabelled ssh: a
    # literal `// 'ssh'` would put an unsupported node on the destruction list
    # (k116). A missing one is hetzner, as apply and validate() read it. An
    # entry skipped for its provider is said, on STDERR (k341): this is the
    # last source, so it may be the only record of a machine, and "No nodes
    # to destroy." was then the only word. With nodes: N it is N copies of
    # one entry, said once, as validate() says it (k322).
    #
    # A hetzner control plane is said too, and not listed (k345). Listed, it
    # was "Deleting <cluster>-cp-N..." and deleted nothing: there is no
    # server id here to delete it by. Its server is one Hetzner created,
    # found by its ocp-cluster label -- the search above, which found nothing
    # if this runs -- or not at all; see _say_hetzner_control_plane.
    #
    # A host Perl calls false (0, '') is no host, as apply reads it
    # (cp_identity, ensure_control_plane_ocpnodes) -- not a machine named 0
    # (k345, as k341 for a pool's).
    unless (@nodes) {
        my $cps    = $config->control_planes;
        my $shared = $config->_control_planes_shared;
        my $idx    = 0;
        for my $i (0 .. $#$cps) {
            my $cp    = $cps->[$i];
            my $where = 'control_planes[' . ($i + 1) . ']';
            unless (OCP::Provider->known_type($cp->{provider} // 'hetzner')) {
                $self->_say_unknown_provider($where, $cp->{provider}, 'that control plane is')
                    unless $shared && $i;
                next;
            }
            $idx++;
            my $prov = $cp->{provider} // 'hetzner';
            if ($prov eq 'hetzner') {
                $self->_say_hetzner_control_plane($config, $where, $searched, $search_error)
                    unless $shared && $i;
                next;
            }
            my $host = $cp->{host} || undef;
            $add->({
                name      => $host // ($config->name . "-cp-$idx"),
                provider  => $prov,
                role      => 'control-plane',
                public_ip => $host // $cp->{public_ip} // '-',
            });
        }
    }

    my @workers = grep { ($_->{role} // '') eq 'worker' } @nodes;
    my @rest    = grep { ($_->{role} // '') ne 'worker' } @nodes;
    return [ @workers, @rest ];
}

# What identifies a machine across the sources: its name, its address, its
# provider id -- any one of them matching is the same machine. A name is
# compared by its first label, the way `ocp apply` names an ssh worker's
# OCPNode after its host (OCP::Cmd::Apply::CR::worker_ocpnodes).
sub _node_keys {
    my ($self, $node, @aliases) = @_;
    my @keys;
    if (defined $node->{name} && length $node->{name}) {
        my ($short) = split /\./, lc $node->{name}, 2;
        push @keys, 'name:'.$short;
    }
    for my $host ($node->{public_ip}, @aliases) {
        next unless defined $host && length $host && $host ne '-';
        push @keys, 'host:'.lc $host;
    }
    push @keys, 'id:'.$node->{providerId}
        if defined $node->{providerId} && length $node->{providerId};
    return @keys;
}

# Every OCPNode, every role, as [ node entry, alias addresses ]. The provider
# TYPE comes from the OCPNodeProvider the node names; failing that from the
# "<type>-default" name `ocp apply` gives the CRs it writes (the derivation
# _report_mislabelled_servers relies on). A node neither answers is named on
# STDERR: it keeps running, and saying nothing about it is the bug this
# closes.
sub _ocpnode_entries {
    my ($self, $api) = @_;
    return unless $api;

    my $list = eval { $api->list('OCPNode', namespace => 'ocp-system') };
    unless ($list) {
        $self->_api_down(1);
        my $why = $@ || "no answer\n";
        chomp $why;
        print STDERR "[!!] Could not read the OCPNodes from the cluster API:\n";
        print STDERR "     $why\n";
        print STDERR "     Workers come from .ocp/status.yaml, Hetzner labels and\n";
        print STDERR "     ocp.yaml only; a worker added with `ocp node add` may be\n";
        print STDERR "     missed and keep running.\n";
        return;
    }

    my %cr   = map { ($_->{metadata}{name} => $_) } $self->provider_crs($api);
    my %type = map { ($_ => $cr{$_}{spec}{type}) } keys %cr;
    $self->_provider_crs(\%cr);

    my @entries;
    for my $cr (map { $api->k8s->object_to_struct($_) } @{ $list->items // [] }) {
        my $name   = $cr->{metadata}{name};
        my $spec   = $cr->{spec}   // {};
        my $status = $cr->{status} // {};
        my $ref    = $spec->{providerRef} // q();

        my $type = $type{$ref};
        ($type) = $ref =~ /\A(\w+)-default\z/ unless defined $type;
        unless (defined $type && OCP::Provider->known_type($type)) {
            print STDERR "[!!] OCPNode $name: provider '$ref' is unknown here;"
                       . " it is NOT torn down.\n";
            next;
        }

        push @entries, [ {
            name      => $name,
            provider  => $type,
            role      => $spec->{role} // 'worker',
            public_ip => $spec->{host} // $status->{publicIP} // '-',
            (defined $status->{providerId}
                ? (providerId => $status->{providerId}) : ()),
            # Which provider -- and so which token -- created it (k181).
            (length $ref ? (provider_ref => $ref) : ()),
        }, grep { defined } $status->{publicIP}, $spec->{host} ];
    }
    return @entries;
}

# A Hetzner adapter for every hetzner-type OCPNodeProvider, built through the
# factory from the CR's token Secret (k181). A CR that gives none -- Secret
# gone, key missing -- is remembered with the reason, which is only printed
# if a server then has no token at all.
#
# A CR from before k98 carries no spec.clusterName, and from_cr refuses it:
# that guard is for CREATING servers, which would come out unfindable. Here
# servers are deleted by id and searched by the cluster name passed in
# explicitly, and a provider CR in this cluster's ocp-system serves this
# cluster -- so the name is filled in rather than the token thrown away.
sub _build_cr_hetzner {
    my ($self, $config, $api) = @_;
    my $crs = $self->_provider_crs;
    for my $name (sort keys %$crs) {
        my $cr = $crs->{$name};
        next unless ($cr->{spec}{type} // '') eq 'hetzner';

        my $spec = { %{ $cr->{spec} } };
        $spec->{clusterName} = $config->name
            unless length($spec->{clusterName} // '');

        my $prov = eval {
            OCP::Provider->from_cr({ %$cr, spec => $spec }, k8s => $api);
        };
        if ($prov) {
            $self->_cr_hetzner->{$name} = $prov;
            next;
        }
        my $why = $@ || "no adapter\n";
        chomp $why;
        $self->_cr_hetzner_error->{$name} = $why;
    }
}

# Every distinct Hetzner token as [ CR name or undef, adapter ], the local
# one first. Two CRs holding one token are one source: the same project,
# searched once.
sub _hetzner_sources {
    my ($self, $local) = @_;
    my (@sources, %seen);
    for my $source ([ undef, $local ],
                    map { [ $_, $self->_cr_hetzner->{$_} ] }
                        sort keys %{ $self->_cr_hetzner }) {
        my $prov = $source->[1] or next;
        my $token = eval { $prov->token } // "$prov";
        next if $seen{$token}++;
        push @sources, $source;
    }
    return @sources;
}

# The adapter that deletes this Hetzner node, or undef (k181). A node that
# names its provider is deleted with that provider's token -- the one that
# created it; the local token may belong to another Hetzner project, where
# the id means nothing. Failing that, the local token. A node that names no
# provider (a control plane from status.yaml) takes the local token, else
# the one `ocp apply` wrote into hetzner-default, else the only hetzner CR
# there is. Never a guess among several: a wrong token fails the delete only
# after the control plane -- and with it the record -- may be gone.
sub _hetzner_for {
    my ($self, $node) = @_;
    my $crs = $self->_cr_hetzner;
    my $ref = $node->{provider_ref};

    return $crs->{$ref} if defined $ref && $crs->{$ref};
    return $self->_local_hetzner if $self->_local_hetzner;
    return if defined $ref;

    return $crs->{'hetzner-default'} if $crs->{'hetzner-default'};
    my @all = values %$crs;
    return @all == 1 ? $all[0] : undef;
}

# Why no adapter reaches this node, in one line for the refusal.
sub _no_token_reason {
    my ($self, $node) = @_;
    my $ref = $node->{provider_ref};
    my $err = defined $ref ? $self->_cr_hetzner_error->{$ref} : undef;
    return "no local Hetzner token, and OCPNodeProvider/$ref gave none: $err"
        if defined $err;
    return "no local Hetzner token, and no OCPNodeProvider/$ref in the cluster"
        if defined $ref;
    return 'no local Hetzner token, and no OCPNodeProvider token'
         . ($self->_api_down || !keys %{ $self->_provider_crs }
            ? ' (cluster API not reachable or no hetzner provider CR)'
            : ' that could stand in for it');
}

# The worker machines ocp.yaml names by host -- `nodes: [host, ...]` and the
# single-host `host:` form alike -- as [ node entry ]. A pool that gives a
# count (`nodes: 2`) names no machine; its servers are found by label or by
# OCPNode, not here.
#
# The single host is read where `ocp apply` reads it (k341): on an ssh pool
# with no nodes: list, and only when Perl calls it true, as
# OCP::Cmd::Apply::CR::worker_ocpnodes does -- host: 0 is no machine named 0.
# A hetzner pool's machines are servers Hetzner creates, at addresses it
# hands out, and a local pool is the machine ocp runs on: apply puts no host
# on their OCPNodes. Read anyway, a hetzner pool's host was listed as a
# machine to destroy and deleted nothing, and a local pool's sent the
# uninstall to 127.0.0.1. A nodes: list is read on every pool whose provider
# destroy knows: on one that counts its machines it is refused before this
# (k323).
#
# A pool whose provider destroy does not know is skipped, never guessed
# (k116), and said, on STDERR (k341).
#
# Which pool takes a host is OCP::Config::_pool_takes_host's answer, the one
# validate() gives (k331). Asked only behind the known-provider gate here and
# in _spec_worker_errors: for a provider it does not know it answers yes, as
# validate() reads such a pool, and destroy reads none (k345).
sub _spec_worker_entries {
    my ($self, $config) = @_;
    my @entries;
    my $n = 0;
    for my $w (@{ $config->workers }) {
        $n++;
        unless (OCP::Provider->known_type($w->{provider} // q())) {
            $self->_say_unknown_provider($config->_pool_where($w, $n),
                $w->{provider}, 'a machine it names is', pool => 1);
            next;
        }
        my @hosts = ref $w->{nodes} eq 'ARRAY'
            ? map { ref $_ ? $_->{host} : $_ } @{ $w->{nodes} }
            : ($config->_pool_takes_host($w) && $w->{host} ? ($w->{host}) : ());
        for my $host (grep { defined && length } @hosts) {
            push @entries, [ {
                name      => $host,
                provider  => $w->{provider},
                role      => 'worker',
                public_ip => $host,
            } ];
        }
    }
    return @entries;
}

# One line on STDERR for a control plane or pool destroy skips because it
# does not know its provider (k341), in validate()'s words for it, then what
# that leaves running. It was skipped without a word. A provider that is not
# set is not said: validate() and apply read a control plane without one as
# hetzner, which the fallback says by itself, and apply read such a pool as
# hetzner too, which names no machine destroy could read.
#
# A pool's provider validate() reads as '' -- false, a YAML boolean -- is a
# missing one there: "provider required", not "invalid provider false"
# (k345). Asked with the test validate() makes, so the two cannot part. A
# control plane's false is invalid in validate() too: it reads a control
# plane's provider as hetzner only when it is absent.
sub _say_unknown_provider {
    my ($self, $where, $prov, $left, %as) = @_;
    return unless ref $prov || length($prov // '');
    my $what = $as{pool} && $prov eq ''
        ? 'provider required'
        : 'invalid provider ' . OCP::Config::_shown_value($prov)
          . ' (must be ' . OCP::Choices::or_list(OCP::Provider->types) . ')';
    print STDERR "[!!] $where: $what -- skipped: $left NOT torn down.\n";
}

# What the control-plane fallback says for a hetzner control plane, in place
# of the delete line that deleted nothing (k345). Its server is found by its
# ocp-cluster label, or not at all: the fallback runs only when that search,
# above it, found nothing.
#
# When a search answered, that is the whole story: on STDOUT, nothing to
# delete. When none did -- no token to search with, or the search failed --
# the server may still run, and nothing here can find it: on STDERR, with
# the label to look for it by. The k98 report after the teardown searches
# the hetzner-default label with the same tokens; with none it has nothing
# to search with either.
sub _say_hetzner_control_plane {
    my ($self, $config, $where, $searched, $search_error) = @_;
    my $label = 'ocp-cluster=' . $config->name;
    my $found = "$where: a hetzner control plane is found by its $label label or not at all";
    if ($searched) {
        print "$found; no server carries it, nothing to delete.\n";
        return;
    }
    my ($error) = split /\n/, $search_error // '';
    my ($why, $fix) = defined $error && length $error
        ? ("the label search failed: $error", 'Fix the cause')
        : ('no Hetzner token searched for it', "Put the project's Hetzner token into secrets.yaml");
    print STDERR "[!!] $found, and $why -- if it runs, it is NOT torn down.\n";
    print STDERR "     $fix and run `ocp destroy` again, or look by hand:\n";
    print STDERR "       hcloud server list -l $label\n";
}

# What validate() says about the nodes: lists _spec_worker_entries reads, in
# its own words (k323): an entry that names no host died there inside Perl
# ("Not a HASH reference"), a host that is a list became a machine named
# ARRAY(0x...), and a hetzner pool's list was read as host names it then
# never deleted.
#
# Only those lists, not all of validate(). Destroy is the way out of a
# cluster: a refusal there for a key it never reads -- a gpu.driver typo, a
# robocop key a newer validate() refuses (k315), a pool count, which destroy
# does not read at all -- would keep paid servers running until someone
# edits a line that has nothing to do with them. So the gate asks exactly
# where the read happens: a pool that is a mapping, with a provider destroy
# knows, and nodes: a list.
#
# And the shape the pools are read out of (k326): workers: a list, each pool
# a mapping. Anything else died inside Perl in _spec_worker_entries, and
# a string there may be a host someone means, which destroy -- not knowing
# its provider, and never guessing one (k116) -- could only skip.
#
# And the pool's own host where _spec_worker_entries reads it (k335): an ssh
# pool with no nodes: list beside it (k341). A list, a mapping or a boolean
# there became one machine named ARRAY(0x...) (or 0, or 1), and the run
# asked for PIN2 to uninstall RKE2 on it. Beside a nodes: list, or on a
# hetzner or local pool, host is not read, as apply does not read it, and
# its shape is not checked: a refusal there would hold a teardown up over a
# key it never reads.
sub _spec_worker_errors {
    my ($self, $config) = @_;
    my $workers = $config->workers;
    return 'workers: must be a list of worker pools, not '
         . OCP::Config::_shown_value($workers)
        unless ref $workers eq 'ARRAY';

    my (@errors, $n);
    for my $w (@$workers) {
        $n++;
        unless (ref $w eq 'HASH') {
            push @errors, "workers[$n]: must be a mapping (a worker pool), not "
                . OCP::Config::_shown_value($w);
            next;
        }
        next if ref $w->{provider}
             || !OCP::Provider->known_type($w->{provider} // q());
        my $where = $config->_pool_where($w, $n);
        if (ref $w->{nodes} eq 'ARRAY') {
            push @errors, $config->_pool_nodes_errors($w, $where);
        }
        elsif ($config->_pool_takes_host($w)
               && defined(my $err = $self->_host_error($w->{host}))) {
            push @errors, "$where: host $err";
        }
    }
    return @errors;
}

# validate()'s words for a host that is no string (k315), or undef.
sub _host_error {
    my ($self, $host) = @_;
    return OCP::Config::_not_a_string($host, 'a host name or IP address');
}

# What validate() says about name (k305), in its words (k335). The name is
# the ocp-cluster label the servers are searched by: a list searched
# ocp-cluster=ARRAY(0x...), so a server status.yaml does not record was
# missed while the run ended "Cluster destroyed." -- and kept billing.
#
# Only a list, a mapping or a boolean, not validate()'s "name is required".
# A name such as '' or 0 is a label like any other, searched as written: a
# cluster applied under it before `ocp apply` validated (k255) carries it,
# and no name destroy could be told instead would find its servers.
sub _spec_name_errors {
    my ($self, $config) = @_;
    my $name = $config->spec->{name};
    return () unless ref $name;
    return "name: must be a string (the cluster's name), not "
         . OCP::Config::_shown_value($name);
}

# What validate() says about the shape of control_planes, in its words
# (k326). Destroy reads every entry's provider for the k98 report -- on each
# run with a Hetzner token, AFTER the deletes and the status cleanup -- and
# the whole entry when the control-plane fallback is the only source left.
# An entry that is no mapping died in the report: the servers were gone and
# status.yaml removed, and the run ended on a Perl error, exit 1, no report.
#
# Refused, not read around. An entry that is no mapping names no provider,
# and destroy never guesses one (k116), so it can be named but not read as a
# machine. Named after the teardown is too late for the case it matters in:
# when that line is the only record of a control plane, the run ends "No
# nodes to destroy." and offers to remove the kubeconfig while that machine
# may still run; and skipped in the report, the line of a hetzner control
# plane no longer asks for the hetzner-default search that names billing
# servers. Nor is it a newer validate() standing between a cluster and its
# teardown: validate() has refused this shape since k296 (and died on it
# before), and `ocp apply` validates first (k255).
#
# And an entry's host where the fallback reads it (k335): an entry it lists,
# an ssh or local one. A list, a mapping or a boolean became the name and
# address of a machine -- ARRAY(0x...) -- that an ssh control plane asked
# PIN2 for and sent the uninstall to. Checked whether or not the fallback
# runs this time: that is known only after the secrets, the cluster API and
# the label search, and this comes before them. As validate() counts them:
# nodes: N stands for N copies of one entry, said once (k322). A hetzner
# control plane's host is not read since k345 -- the fallback names it by
# its label, and lists no machine for it -- so its shape is not checked.
#
# Not a provider, a server_type, a location, an image, a count or the bound
# of seven, which destroy reads around or not at all.
sub _spec_control_plane_errors {
    my ($self, $config) = @_;
    my $raw = $config->spec->{control_planes};
    return 'control_planes: must be a mapping (one control plane, or nodes: N of them) '
         . 'or a list of mappings, not ' . OCP::Config::_shown_value($raw)
        if defined $raw && ref $raw ne 'HASH' && ref $raw ne 'ARRAY';

    my $cps = $config->control_planes;
    my @errors;
    for my $i (0 .. ($config->_control_planes_shared ? 0 : $#$cps)) {
        my $cp  = $cps->[$i];
        my $idx = $i + 1;
        unless (ref $cp eq 'HASH') {
            push @errors, "control_planes[$idx]: must be a mapping (one control plane), not "
                . OCP::Config::_shown_value($cp);
            next;
        }
        my $prov = $cp->{provider} // 'hetzner';
        next if ref $prov || !OCP::Provider->known_type($prov) || $prov eq 'hetzner';
        my $err = $self->_host_error($cp->{host}) // next;
        push @errors, "control_planes[$idx].host: $err";
    }
    return @errors;
}

# robocop reconciles OCPNodes: left running, it would see a worker vanish
# under it and provision a replacement -- a new paid server, created after the
# label search, that nothing is left to delete. Scaled to zero before the
# first delete. Best-effort: a cluster without robocop answers 404.
sub _stop_robocop {
    my ($self, $api) = @_;
    return if !$api || $self->_api_down;
    my $ok = eval {
        $api->patch('Deployment', 'robocop',
            namespace => 'ocp-system',
            patch     => { spec => { replicas => 0 } },
            type      => 'merge',
        );
        1;
    };
    if ($ok) {
        print "robocop stopped.\n";
        return 1;
    }
    my $why = $@ // q();
    return if $why =~ /\b404\b/;
    chomp $why;
    print STDERR "  Warning: could not stop robocop ($why);"
               . " it may re-provision a worker.\n";
    return;
}

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config = OCP::Config->new(file => $file);

    # First, before a PIN is asked or the cluster or a server is reached
    # (k323, k326, k335), as `ocp apply` refuses an invalid ocp.yaml (k255).
    # In validate()'s order: the name, the control planes, then the pools.
    if (my @errors = ($self->_spec_name_errors($config),
                      $self->_spec_control_plane_errors($config),
                      $self->_spec_worker_errors($config))) {
        my $s = @errors == 1 ? '' : 's';
        die "$file has " . scalar(@errors) . " error$s:\n"
          . join('', map { "  - $_\n" } @errors)
          . "Nothing was deleted: ocp destroy reads the cluster's name and the machines and "
          . "providers of the control planes and worker pools in ocp.yaml, and checks their "
          . "shape before it touches the cluster or a server. Fix the line$s above and run "
          . "it again.\n";
    }

    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    # Initialize Hetzner provider if token available
    my $hetzner_token = $secrets->hetzner_token;
    my $hetzner_prov;
    if ($hetzner_token) {
        $hetzner_prov = OCP::Provider->for_spec(
            { provider => 'hetzner' },
            token        => $hetzner_token,
            cluster_name => $config->name,
        );
    }
    $self->_local_hetzner($hetzner_prov);

    # The cluster API, if it still answers: its OCPNodes are the only record
    # of the workers robocop brought up (k177), its provider CRs hold the
    # tokens a worker was created with (k181).
    my $api   = $self->_cluster_api($config);
    my $nodes = $self->_collect_nodes($config, $hetzner_prov, $api);

    # A paid server no token reaches is refused BEFORE anything is deleted
    # (k181). It used to be skipped without a word and the run ended on
    # "Cluster destroyed." while it kept billing. Going on with the rest
    # would be worse than stopping: the control planes take the API along,
    # and with it the OCPNode and the Secret -- the only record of that
    # server and the only token that could still delete it.
    my @no_token = grep {
        $_->{provider} eq 'hetzner' && $_->{providerId}
            && !$self->_hetzner_for($_)
    } @$nodes;
    if (@no_token) {
        print STDERR "[!!] Nothing was deleted: no Hetzner API token reaches these\n";
        print STDERR "     servers. They keep running and keep billing:\n";
        for my $node (@no_token) {
            printf STDERR "       - %s (id %s, %s)\n",
                   $node->{name}, $node->{providerId}, $node->{public_ip} // '-';
            print  STDERR "         ".$self->_no_token_reason($node)."\n";
        }
        print STDERR "     Put the project's Hetzner token into secrets.yaml (or\n";
        print STDERR "     restore the provider's Secret in ocp-system), then run\n";
        print STDERR "     `ocp destroy` again -- or delete them by hand:\n";
        print STDERR "       hcloud server delete <id>\n";
        return 1;
    }

    unless (@$nodes) {
        print "No nodes to destroy.\n";

        # The k98 report, as at the end of a teardown -- here before the
        # question, so the servers it names are known before the kubeconfig
        # goes. A hetzner control plane in the fallback used to reach it
        # through the delete line that deleted nothing; said instead (k345),
        # it leaves nothing to list, and the run lands here.
        $self->_report_mislabelled_servers($config,
            $hetzner_prov // $self->_hetzner_for({}));

        # k78: this early-return used to skip the cleanup that runs at
        # the bottom of execute(). It is exactly the shape a project takes
        # after a cluster was torn down out of band — status.yaml with
        # `nodes: []`, the spec slimmed down, no orphans at Hetzner — and
        # leaving deployed.yaml behind made the next `ocp apply` compare a
        # fresh cluster against the hashes of one that was gone (ADR 0004).
        # --keep_status opts out below.
        #
        # k304: but not unasked. An empty node list is also what a stale
        # status.yaml or a read that failed looks like while the cluster is
        # alive, and the kubeconfig is the way into it. So the same yes as
        # the main path -- a person at a terminal, or --force -- naming the
        # files. Nothing to remove, nothing to ask.
        my @files = $self->_project_state_files($config);
        return 0 unless @files;

        my $listed = join ', ',
            map { path($_)->relative($config->project_dir) } @files;
        my $state  = "the local state of cluster '".$config->name."' (".$listed.')';
        unless ($self->force || $self->confirmed(
            question => 'Remove '.$state.'?',
            action   => 'removing '.$state,
            switch   => '--force',
        )) {
            print STDERR "Aborted; nothing was removed.\n";
            return 1;
        }

        $self->_cleanup_project_state($config);
        return 0;
    }

    print "Cluster: ", $config->name, "\n";
    print "Nodes to destroy:\n";
    for my $node (@$nodes) {
        print "  - $node->{name} ($node->{provider}, $node->{public_ip})\n";
    }
    print "\n";

    # Nothing has been deleted or changed up to here; a refusal leaves the
    # servers, robocop and the local state exactly as they were. Deleting the
    # cluster's servers needs a person's yes at a terminal; --force is the way
    # to confirm without one (k301).
    unless ($self->force || $self->confirmed(
        question => 'Are you sure you want to destroy this cluster?',
        action   => "destroying cluster '".$config->name."'",
        switch   => '--force',
    )) {
        print STDERR "Aborted; nothing was deleted.\n";
        return 1;
    }

    $self->_stop_robocop($api);

    # The key for the ssh-provider nodes: fetched ONCE, BEFORE the loop, in an
    # eval of its own. Three decisions in one block, and all three are about
    # never letting a cleanup step cost someone money.
    #
    #   * Why it is needed at all now. Until the two-tier decision this branch
    #     used the bootstrap key and could not fail: an unencrypted file, or
    #     no teardown. In secure mode there is no bootstrap key any more — an
    #     ssh machine trusts the admin key like every other machine — so the
    #     lookup is behind PIN2 and CAN die: wrong PIN, no terminal, no
    #     keys.yaml.
    #
    #   * Why before the loop. Each delete sits in its own eval so a host that
    #     is already gone is a warning, not the end of the run. A dying lookup
    #     inside the loop but outside those evals would abort the teardown
    #     midway — on a mixed cluster that leaves PAID Hetzner servers running
    #     because an ssh worker's key could not be unlocked. Hetzner deletes go
    #     through the API and need no SSH at all, so they must never depend on
    #     this.
    #
    #   * Why only when an ssh node is actually in the list. A pure Hetzner
    #     teardown must not grow a PIN2 prompt it never had.
    #
    # A failure here therefore downgrades to "the uninstall script did not
    # run on those machines", which is recoverable by hand, and says so.
    my $needs_ssh_key = grep {
        ($_->{provider} // '') eq 'ssh'
            && $_->{public_ip} && $_->{public_ip} ne '-'
    } @$nodes;

    my $ssh_key;
    if ($needs_ssh_key) {
        $ssh_key = eval {
            $self->cluster_ssh_key($config,
                provider => 'ssh',
                reason   => 'ocp destroy',
            );
        };
        unless ($ssh_key) {
            my $why = $@ || "unknown error\n";
            chomp $why;
            print STDERR "\n";
            print STDERR "[!!] Could not obtain the SSH key for the ssh-provider nodes:\n";
            print STDERR join('', map { "     $_\n" } split /\n/, $why);
            print STDERR "     Their RKE2/K3s uninstall will be SKIPPED. Everything\n";
            print STDERR "     that costs money is deleted through the provider API\n";
            print STDERR "     and is unaffected.\n";
            print STDERR "     To clean those machines up later, run on each of them:\n";
            print STDERR "       rke2-uninstall.sh   # or k3s-uninstall.sh / k3s-agent-uninstall.sh\n";
            print STDERR "\n";
        }
    }

    # Delete nodes. $hinted keeps the migration diagnosis to one appearance
    # per run: six unreachable machines are six warnings, not six essays.
    #
    # @undeleted records the nodes whose PROVIDER delete failed -- a paid
    # server the API did not remove. It gates the cleanup below: status.yaml
    # is the only local record of a Hetzner server's providerId, so throwing
    # it away while the server is still running strands a billing machine with
    # no handle to find it by. That is the money-losing failure the ssh-key
    # block above guards against, in the one delete path that was not. An
    # existing-host (ssh/local) uninstall that fails is deliberately NOT
    # counted here: the machine is pre-existing, OCP never provisioned or
    # billed it, and the k116 branch below already treats "host already gone"
    # as a recoverable warning, not a stranded resource.
    #
    # Those go to @still_installed instead, as [ host, reason ]: the machines
    # that keep their RKE2/K3s install. They do not hold the cleanup back --
    # nothing in the local state is needed to reach them again, and a host
    # that is already gone would otherwise make the project impossible to tear
    # down -- but they do make the run incomplete: named at the end, exit 1
    # (k180).
    #
    # @unchecked, as [ host, [ warnings ] ]: machines uninstalled cleanly, but
    # where the uninstall had no tool for part of Cilium's datapath (no tc, no
    # iptables backend with -save and -restore), so that part may still be
    # there (k213). Not a failure -- the library's own outcome check passed --
    # but the next install on such a host meets it, so the run ends by naming
    # them and asking for a reboot.
    my $hinted = 0;
    my @undeleted;
    my @still_installed;
    my @unchecked;
    for my $node (@$nodes) {
        print "Deleting $node->{name}...\n";

        # Every such node has an adapter: the refusal above saw to it (k181).
        if ($node->{provider} eq 'hetzner' && $node->{providerId}) {
            my $prov = $self->_hetzner_for($node);
            # The address goes along so its host key leaves known_hosts with
            # the machine (k168).
            my $ip = ($node->{public_ip} // '-') ne '-' ? $node->{public_ip} : undef;
            eval {
                $prov->delete_server($node->{providerId},
                    ($ip ? (host => $ip) : ()));
            };
            if ($@) {
                print STDERR "  Warning: $@\n";
                push @undeleted, $node;
            }
        }
        # An existing-host node (ssh, local): the machine survives, so what we
        # remove is what we installed on it. The branch used to hard-code
        # `eq 'ssh'`, so a local-provider node fell through with nothing --
        # the same way a future provider type would silently fall through
        # today. Both consume OCP::Role::Provider::ExistingHost, so the
        # delete call is identical; only ssh needs the key (the cluster
        # key comes from above, resolved or already known to be unavailable
        # -- nothing in this branch may die).
        #
        # The uninstall target is the provider's OWN resolve_host, not the
        # node's public_ip -- so which nodes can be cleaned up is the provider's
        # call, expressed through the ExistingHost contract, rather than a
        # string test on the provider name here. A spec-fallback node with no
        # `host` in ocp.yaml arrives with public_ip '-'; that is passed through
        # as "no host". ssh has nowhere to go without one -- resolve_host dies
        # and the node is skipped, exactly as before -- while the local
        # provider ignores the host entirely (resolve_host is a constant
        # 127.0.0.1) and still tears the box down. That last case is the bug
        # this closes: a `provider: local` cluster discovered only via the spec
        # fallback used to keep RKE2 installed after `ocp destroy` because the
        # old `public_ip ne '-'` gate dropped it (k146).
        elsif (OCP::Provider->known_type($node->{provider} // q())
               && $node->{provider} ne 'hetzner') {
            my $host_prov = OCP::Provider->for_spec(
                { provider => $node->{provider} },
                ($node->{provider} eq 'ssh' && $ssh_key
                    ? (ssh_key_path => $ssh_key->path)
                    : ()),
            );

            # '-' is the spec-fallback marker for "no host was recorded"; hand
            # the provider undef in that case so ssh's resolve_host dies rather
            # than treating '-' as a literal target, while local ignores it.
            my $ip = ($node->{public_ip} && $node->{public_ip} ne '-')
                ? $node->{public_ip} : undef;
            my $target = eval { $host_prov->resolve_host(host => $ip) };
            next unless defined $target && length $target;

            if ($node->{provider} eq 'ssh') {
                unless ($ssh_key) {
                    print STDERR "  Skipped: no SSH key, $target keeps its RKE2/K3s install.\n";
                    push @still_installed, [ $target, 'no SSH key' ];
                    next;
                }
            }

            print "  Uninstalling RKE2/K3s on $target...\n";
            my $result = eval {
                $host_prov->delete_server(undef, host => $target)
            };
            # ExistingHost::delete_server dies with the host, the exit code and
            # the uninstaller's stderr (k175); a provider that returns a
            # non-zero exit instead is the same failure. Either way the reason
            # is what gets printed -- a fixed "may already be down" threw it
            # away and left the operator guessing (k180).
            my $why = $@;
            if (!$why && (!ref $result || ($result->{exit} // 0) != 0)) {
                my $exit   = ref $result ? $result->{exit} : '?';
                my $stderr = ref $result ? $result->{stderr} // '' : '';
                $stderr =~ s/\s+\z//;
                $why = "Uninstall of RKE2/K3s on $target failed (exit $exit)"
                     . (length $stderr ? ": $stderr" : '');
            }
            if ($why) {
                chomp $why;
                print STDERR "  Warning: could not uninstall on $target:\n";
                print STDERR join('', map { "    $_\n" } split /\n/, $why);
                push @still_installed, [ $target, $why ];
                # The migration hint names the bootstrap-vs-admin key story,
                # which is ssh-only. A local uninstall has no key.
                if ($node->{provider} eq 'ssh' && !$hinted++) {
                    print STDERR $ssh_key->migration_hint;
                }
            } else {
                print "  RKE2/K3s uninstalled on $target.\n";
                my $warnings = ref $result eq 'HASH' ? $result->{warnings} // [] : [];
                push @unchecked, [ $target, $warnings ] if @$warnings;
            }
        }
    }

    # Clear status + kubeconfig. Pulled into a helper so the early-return
    # path above ("no nodes to destroy") and the main path land at the same
    # code; the early-return bypass used to leave .ocp/deployed.yaml behind
    # when a cluster was torn down out of band (k78).
    #
    # Skipped entirely when a provider delete failed (k140): the local state
    # is the only record of the surviving server's providerId, and removing it
    # would leave a paid machine running with nothing to find it by. Keeping
    # status.yaml (and deployed.yaml, and the kubeconfig that still reaches the
    # live cluster) intact lets a re-run pick up exactly where this one
    # stopped once the cause is fixed.
    unless (@undeleted) {
        $self->_cleanup_project_state($config);
    }

    # Last, so it is the thing left on screen: a teardown that reported success
    # while paid machines kept running is the failure mode this is here for.
    $self->_report_mislabelled_servers($config,
        $hetzner_prov // $self->_hetzner_for({}));

    # A failed provider delete is the money-losing case: say so plainly, name
    # the survivors, and exit non-zero so callers and CI do not read this as a
    # clean teardown. Diagnosis on STDERR, per the output-channel rule (k105);
    # the "Cluster destroyed." payload below is only ever printed when the run
    # really did tear everything down.
    if (@undeleted) {
        print STDERR "\n";
        printf STDERR "[!!] Teardown INCOMPLETE: %d node(s) could not be deleted and\n",
               scalar @undeleted;
        print  STDERR "     are still running (and, at Hetzner, still billing):\n";
        for my $node (@undeleted) {
            printf STDERR "       - %s (%s, id %s)\n",
                   $node->{name}, $node->{provider},
                   $node->{providerId} // $node->{public_ip} // '?';
        }
        print  STDERR "     .ocp/status.yaml is kept so a re-run can find them by\n";
        print  STDERR "     providerId: fix the cause, then run `ocp destroy` again.\n";
    }

    # The machines that are not billed but not clean either (k180). The same
    # exit code as above: a caller needs to know "not everything is gone",
    # and the STDERR list says which kind of leftover it is.
    if (@still_installed) {
        print STDERR "\n";
        printf STDERR "[!!] Teardown INCOMPLETE: %d machine(s) keep their RKE2/K3s install:\n",
               scalar @still_installed;
        for my $left (@still_installed) {
            my ($host, $why) = @$left;
            my ($first) = split /\n/, $why;
            print STDERR "       - $host: $first\n";
        }
        print  STDERR "     Nothing is billed for them through OCP. Once they are\n";
        print  STDERR "     reachable, run on each of them:\n";
        print  STDERR "       rke2-uninstall.sh   # or k3s-uninstall.sh / k3s-agent-uninstall.sh\n";
    }

    if (@unchecked) {
        print STDERR "\n";
        printf STDERR "[!] %d machine(s) uninstalled, but part of Cilium's datapath could not be\n",
               scalar @unchecked;
        print  STDERR "    checked there and may still be on them:\n";
        for my $left (@unchecked) {
            my ($host, $warnings) = @$left;
            print STDERR "       - $host: $_\n" for @$warnings;
        }
        print  STDERR "    Reboot them before RKE2/K3s is installed on them again.\n";
    }

    return 1 if @undeleted || @still_installed;

    print "\nCluster destroyed.\n";

    return 0;
}

# Remove the local files a successful destroy is meant to leave behind. Both
# paths through execute() -- the early "no nodes to destroy" return and the
# "nodes deleted, now tidy up" tail -- call this, so the local state dies with
# the cluster it described regardless of whether anything was actually torn
# down on the wire (k78).
#
# deployed.yaml goes with status.yaml, and for the same reason: both describe
# the cluster that was just deleted (ADR 0004). Leaving the manifest hashes
# behind made the next `ocp apply` compare a brand new cluster against the
# components of the old one — it announced "Registry already deployed (up to
# date)" on an empty ocp-system and then pointed CoreDNS at a registry that
# was never rolled out. Nothing on the way to that was an error, so nothing
# reported one.
#
# --keep_status is the documented opt-out; it covers status.yaml and
# deployed.yaml only. The encrypted kubeconfig is removed unconditionally —
# it is cluster access material, not cluster state.
sub _cleanup_project_state {
    my ($self, $config) = @_;

    my $kubeconfig = $self->_kubeconfig_file($config);
    for my $file ($self->_project_state_files($config)) {
        unlink $file;
        print $file eq $kubeconfig ? "Encrypted kubeconfig removed.\n"
                                   : 'Removed '.path($file)->basename.".\n";
    }
}

# The files _cleanup_project_state removes, those that exist, in the order it
# removes them. One list, so what the no-nodes question names (k304) is what
# goes.
sub _project_state_files {
    my ($self, $config) = @_;
    return grep { -f $_ }
        ($self->keep_status ? () : ($config->status_file, $config->deployed_file)),
        $self->_kubeconfig_file($config);
}

sub _kubeconfig_file {
    my ($self, $config) = @_;
    return $config->project_dir->child('kubeconfig.yaml')->stringify;
}

1;

__END__

=synopsis

    ocp destroy            # prompts for confirmation
    ocp destroy --force    # skip prompt
    ocp destroy --keep_status   # leave .ocp/status.yaml and .ocp/deployed.yaml behind

=description

C<ocp destroy> tears down every node recorded for the current cluster,
across both providers:

=over 4

=item *

Hetzner — each node carrying a C<providerId> is deleted via
L<OCP::Provider::Hetzner/delete_server>; the encrypted SSH key the
project uploaded is left in place and may be re-used by a later C<ocp apply>.

The token comes from where the server came from (C<k181>).  A node whose
OCPNode names an C<OCPNodeProvider> is deleted with the token in that
provider's Secret, read while the cluster API answers; a node that names
none (a control plane from C<status.yaml>) with the local token from
C<secrets.yaml>, else the one in C<hetzner-default>.  The label search runs
under every distinct token.  A server that no token reaches stops the
teardown B<before anything is deleted>: its name, id and address and the
reason are printed on STDERR and the command returns 1.  Going on without it
would take the control plane down, and with it the OCPNode and the Secret —
the only record of that server and the only token that could delete it.

=item *

SSH / local — the RKE2/K3s uninstaller is run on the host.  A failure here
does not stop the tear-down: the reason the uninstaller gave (host, exit
code, its stderr) is printed on STDERR and the next machine is tried.  At
the end every machine that kept its install is listed with its reason and
the command returns 1 (C<k180>).  The local state is still removed — the
machine is not billed through OCP and nothing in C<status.yaml> is needed to
reach it again, while holding the cleanup back would make a project whose
host is already gone impossible to tear down.

=back

The key those SSH uninstalls use is resolved once, before the loop, and only
when the node list actually contains an ssh-provider machine (see
L<OCP::ClusterKey> — in secure mode that is the PIN2-protected admin key, so
it can fail; a Hetzner-only teardown never asks).  B<A failure to obtain it
does not stop the teardown.>  It is reported, the uninstall steps are skipped
with a per-host line, and every Hetzner server is still deleted through the
API — those cost money, an uninstall script does not.

Before the final line the teardown looks once more, under the C<ocp-cluster>
labels C<ocp apply> would have written a provider CR as
(C<< <type>-default >>), and B<names> anything still running there.  Those are
servers created before the fix for C<k98>, when the worker path took the
provider CR's own name for the cluster name: they belong to this cluster but
carry a label no teardown searches.  They are reported, never deleted — the
label is generic, so a match can belong to another OCP cluster in the same
Hetzner project.  The printed C<hcloud> selector is the way to inspect and
remove them by hand, and it is also the way to find servers under a provider
that was added with C<ocp provider add --name> rather than by C<ocp apply>.
The report runs when no node was found to delete as well, before the
question about the local state (C<k345>).

Before anything else -- before a PIN is asked, the cluster API or a provider
is reached -- the C<nodes:> lists of the worker pools are checked, the lists
destroy reads machines off (C<k323>).  A list L<OCP::Config/validate>
refuses -- an entry that is no host name, address or mapping with C<host>,
or a list at all on a pool that counts its machines -- stops the teardown
with C<validate()>'s lines, all at once, on STDERR and exit 1, and nothing
is deleted.  So is the shape those lists and the control planes are read out
of (C<k326>): a C<control_planes> that is neither a mapping nor a list, a
C<control_planes> list entry that is no mapping, a C<workers> that is no list,
a worker pool that is no mapping.  Such an entry names no provider, and
destroy never guesses one, so it could only be skipped -- and a string there
may be the host of a control plane that nothing else records.  So is a
C<name>, or a C<host> where destroy reads one, that is a list, a mapping or
a boolean (C<k335>): the name is the C<ocp-cluster> label the servers are
searched by, and C<name: [prod]> missed every server under C<prod> that
F<.ocp/status.yaml> does not record; a host became a machine named
C<ARRAY(0x...)>.  A pool's C<host> is read on an ssh pool whose C<nodes:> is
no list -- never on a hetzner or local pool, where C<ocp apply> does not read
it either (C<k341>) -- a control plane's on an ssh or local one, which the
fallback below lists (a hetzner one it does not, since C<k345>).  Only
those: an F<ocp.yaml> that C<validate()> refuses for a key destroy reads
around or does not read -- C<gpu>, C<robocop>, a pool's
count, an unknown provider, a missing C<server_type>, a C<server_type>,
C<location> or C<image> of the wrong shape, more than seven control planes,
a C<name> of C<''> or C<0> (searched as written) -- is still torn down, so a
newer C<validate()> never stands between a cluster and its teardown.

The node list is merged from every source, one entry per machine
(matched by name, address or provider id): C<.ocp/status.yaml> (the
control planes); every OCPNode in the cluster, all roles, while the
cluster API answers (the only record of the workers robocop or
C<ocp node add> brought up); the Hetzner servers carrying this cluster's
label (L<OCP::Provider::Hetzner/list_servers_by_cluster>); and the worker
pools of C<ocp.yaml> that name their machines: the C<nodes: [...]> list, and
the single C<host:> of an ssh pool, read as C<ocp apply> reads it -- a host
Perl calls false, such as C<0>, names no machine (C<k341>).  A hetzner pool's
machines are found by label or by OCPNode, a local pool's by OCPNode.  The
C<control_planes> section of C<ocp.yaml> is a last resort, used only when
nothing else found a node.  A worker pool, or a control plane in that last
resort, whose provider destroy does not know is skipped and named on STDERR
with C<validate()>'s words for its provider (C<k341>) -- for a pool's
C<provider: false> that is C<provider required> (C<k345>).  A control plane
there is read as C<ocp apply> reads it (C<k345>): with no C<provider> it is
hetzner, and a C<host> Perl calls false, such as C<0>, names no machine.  A
hetzner one is not listed: there is no server id to delete it by, and its
server is found by its C<ocp-cluster> label -- the search before the last
resort, which found nothing if it runs -- or not at all.  The run says so,
on STDOUT when that search answered, and on STDERR, with the C<hcloud>
selector to look for it by hand, when none did (no token, or the search
failed): then it may still run.  An API that does not
answer is reported on STDERR and the teardown continues from the other
sources (C<k177>).

Workers are torn down before the control planes, and robocop is scaled to
zero first so it does not provision a replacement for a worker it sees
disappear.  A Hetzner server is deleted together with its known_hosts
entries (C<k168>).

After the run, both C<.ocp/status.yaml> and C<.ocp/deployed.yaml> are
removed (unless C<--keep_status> is set) and the encrypted C<kubeconfig.yaml>
is deleted.  Leaving C<deployed.yaml> behind was the bug behind C<ADR 0004>:
a fresh C<ocp apply> compared a brand-new cluster against the hash file of
the previous one and announced every component as "up to date" against a
registry that was never rolled out.  Cleanup runs even when no nodes were
found to delete (C<k78>) — a teardown that discovers nothing on the
wire is exactly the shape a project directory takes after a cluster was
torn down out of band.  It is asked for first, the way the teardown is
(C<k304>): an empty node list is also what a stale C<status.yaml> or a failed
read looks like while the cluster is alive, and the kubeconfig is the way in.
The question names the files that would go; it needs a person at a terminal
or C<--force>, and a no keeps every file and returns 1.  With nothing to
remove nothing is asked.  It is B<skipped>, though, when any provider delete
failed: the survivor is still running (and still billing) and
C<status.yaml> is the only local record of its C<providerId>, so keeping it
is what lets a re-run finish the job (C<k140>).

=opt force

    --force, -f

Skip the C<Are you sure?> prompt; the only way to destroy without a
terminal.  Otherwise the question is asked on STDERR, and the command aborts
unless the answer is C<y> or C<yes> (case-insensitive).  An abort deletes
nothing, leaves the local state alone and returns 1.

The confirmation is asked on a terminal only (C<k301>).  Without one (a pipe,
a CI step, a here-string, a closed STDIN) the command does not read STDIN at
all: it says on STDERR that it needs a person at a terminal or C<--force>,
deletes nothing and returns 1.  A piped C<y> is not a confirmation.

When no node is found, C<--force> likewise skips the question before the
local state is removed (C<k304>).

=opt keep_status

    --keep-status

Keep C<.ocp/status.yaml> and C<.ocp/deployed.yaml> in place after
teardown.  Useful when the next step is C<ocp apply> against the same
spec and you want the reconcile path to start from a known-good hash set.

=method execute

    $cmd->execute($args, $chain)

Dies with the lines of L<OCP::Config/validate> on a worker pool C<nodes:>
list it cannot read (C<k323>), on a C<control_planes> or C<workers> in a
shape it cannot read, an entry that is no mapping among them (C<k326>), or
on a C<name> or a C<host> it reads that is no string (C<k335>), before it
touches anything.  Then lists the
candidate nodes, asks for confirmation on a terminal (unless
C<--force>, the only way without a terminal; without one it returns 1 having
touched nothing), deletes each via its provider and, on a clean run, removes
the local state and the encrypted kubeconfig and returns 0.  A failed or skipped SSH/local
uninstall does not stop the run and does not keep the local state, but it is
named with its reason at the end and the command returns 1 (C<k180>).  A
failed B<provider>
delete — a Hetzner server the API did not remove — is different: the local
state is B<kept> so a re-run can find the survivor by its C<providerId>, the
teardown is reported B<incomplete> on STDERR, and the command returns
non-zero (C<k140>).

An uninstall that succeeded but could not check part of Cilium's datapath on
its machine -- no C<tc>, no iptables backend with C<-save> and C<-restore>
(L<Rex::Rancher::Uninstall/uninstall_warnings>) -- is not a failure: its
warnings go to STDERR as they come, and the run ends by naming those machines
with them and asking for a reboot before the next install (C<k213>).

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Status>, L<OCP::Provider::Hetzner>,
L<OCP::Config>, L<OCP::Secrets>

=cut
