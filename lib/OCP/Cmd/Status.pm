package OCP::Cmd::Status;
# ABSTRACT: Show cluster status

use Moo;
use MooX::Cmd;
use MooX::Options;
use JSON::MaybeXS ();

use OCP;
use OCP::Config;
use OCP::Drift;
use OCP::Kubernetes;
use OCP::Secrets;
use OCP::Versions;

with 'OCP::Role::Cmd';

=opt json

    --json

Print one canonical JSON document on STDOUT instead of the text report;
diagnostics go to STDERR.  See L</JSON OUTPUT>.

=cut

option json => (
    is  => 'ro',
    doc => 'Print the status as canonical JSON on STDOUT (diagnostics on STDERR, no timestamps)',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;

    unless (-f $file) {
        die "Config file '$file' not found. Run 'ocp init' first.\n";
    }

    my $config = OCP::Config->new(file => $file);

    return $self->_execute_json($config, $file) if $self->json;

    print "Cluster: ", $config->name, "\n";
    print "Config:  $file\n";
    print "\n";

    # Spec summary
    my $cps = $config->control_planes;
    my @workers = @{$config->workers};

    print "=== Spec ===\n";
    # Show what would actually be installed, not the word 'latest' — an unpinned
    # version means the manifest decides, and that is a concrete number.
    my $dist = $config->distribution;
    my $dist_version = $config->version
        || OCP::Versions->get_component_version($dist)
        || 'latest';
    print "Distribution: $dist $dist_version\n";

    my $cp_count = scalar @$cps;
    my $cp_provider = $cps->[0]{provider} || 'hetzner';
    my $cp_type     = $cps->[0]{server_type};
    print "Control Planes: $cp_count (",
          join(', ', ($cp_type ? $cp_type : ()), $cp_provider), ")\n";

    for my $pool (@workers) {
        my $nodes = ref($pool->{nodes}) eq 'ARRAY' ? scalar(@{$pool->{nodes}}) : ($pool->{nodes} // $pool->{count} // 0);
        my $provider = $pool->{provider} // 'ssh';
        print "Workers ($pool->{name}): $nodes ($provider)\n";
    }
    print "\n";

    # Live status via the Kubernetes API (typed client)
    unless ($config->cluster_exists) {
        print "=== Status ===\n";
        print "No cluster deployed yet. Run 'ocp apply' to deploy.\n";
        return 0;
    }

    print "=== Status ===\n";
    print "Cluster exists (kubeconfig.yaml found)\n\n";

    # Decrypt kubeconfig to temp file
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;

    unless ($kc_content) {
        print "ERROR: Cannot decrypt kubeconfig.yaml\n";
        print "Make sure .ocp/age.key exists.\n";
        return 1;
    }

    my $k8s = OCP::Kubernetes->new(kubeconfig => $kc_content);

    my $nodes = eval { $k8s->list_nodes };
    if (!$nodes || $@) {
        my $error = $@ || 'Unknown Kubernetes API error';
        print "WARNING: Cannot connect to cluster API\n";
        print "Error: $error\n";
        print "\nKubeconfig available. Export with: ocp kubeconfig -e\n";
        return 1;
    }
    my @nodes = @$nodes;

    unless (@nodes) {
        print "No nodes found in cluster.\n";
        return 0;
    }

    # Show nodes
    printf "%-20s %-10s %-20s %-16s %s\n",
        'NAME', 'STATUS', 'ROLES', 'VERSION', 'INTERNAL-IP';
    print "-" x 80, "\n";

    for my $node (@nodes) {
        my $name = $k8s->node_name($node);
        my $version = $k8s->node_version($node);
        my $ready = $k8s->node_ready($node) ? 'Ready' : 'NotReady';
        my $roles = $k8s->node_roles($node);
        my $internal_ip = $k8s->node_internal_ip($node);

        printf "%-20s %-10s %-20s %-16s %s\n",
            $name, $ready, $roles, $version, $internal_ip;
    }

    # GPU Status
    my $gpu_nodes = $k8s->gpu_nodes;
    if (@$gpu_nodes) {
        print "\n=== GPU Status ===\n";
        for my $gnode (@$gpu_nodes) {
            my $gname = $k8s->node_name($gnode);
            my $gcount = $k8s->node_gpu_count($gnode);
            printf "  %s: %dx NVIDIA GPU\n", $gname, $gcount;
        }
    }

    # Drift between what ocp.yaml/the version manifest say and what runs.
    #
    # rex_prober adds OCP::Drift's SSH-side detection (host residue no API query
    # can see). It is non-prompting and returns undef when no key is at hand, so
    # this stays as read-only and interaction-free as the rest of the command --
    # an unreachable host or a missing key degrades to "not checked", never a
    # prompt and never a failure of `ocp status`.
    my $drift = eval {
        OCP::Drift->new(
            config     => $config,
            api        => $k8s->api,
            rex_prober => $self->rex_prober($config),
        )->detect;
    } // [];

    if (@$drift) {
        print "\n=== Drift ===\n";
        print "$_\n" for OCP::Drift->format_lines($drift);

        my $fixable = grep { $_->{remedy} } @$drift;
        print "\n$fixable of ", scalar(@$drift),
              " can be reconciled automatically: run 'ocp apply'.\n" if $fixable;
    }

    print "\n";
    print "Kubeconfig: ocp kubeconfig -e\n";

    return 0;
}

# The --json form of the report. Same data as the text form, one object, and
# nothing else on STDOUT; whatever went wrong is told on STDERR as well.
sub _execute_json {
    my ($self, $config, $file) = @_;

    my @workers = @{ $config->workers };
    my $cps     = $config->control_planes;
    my $dist    = $config->distribution;

    my %out = (
        cluster  => $config->name,
        config   => $file,
        deployed => JSON::MaybeXS::false(),
        nodes    => [],
        drift    => [],
        spec     => {
            distribution  => $dist,
            version       => ($config->version || OCP::Versions->get_component_version($dist) || 'latest'),
            control_planes => {
                count       => scalar(@$cps),
                provider    => ($cps->[0]{provider} || 'hetzner'),
                server_type => $cps->[0]{server_type},
            },
            workers => [ map {
                +{
                    name     => $_->{name},
                    provider => ($_->{provider} // 'ssh'),
                    nodes    => (ref($_->{nodes}) eq 'ARRAY' ? scalar(@{$_->{nodes}}) : ($_->{nodes} // $_->{count} // 0)) + 0,
                }
            } @workers ],
        },
    );

    my $exit = $self->_collect_json($config, \%out);

    print JSON::MaybeXS->new(canonical => 1, pretty => 1)->encode(\%out);
    return $exit;
}

sub _collect_json {
    my ($self, $config, $out) = @_;

    return 0 unless $config->cluster_exists;
    $out->{deployed} = JSON::MaybeXS::true();

    my $secrets    = OCP::Secrets->new(project_dir => $config->project_dir);
    my $kc_content = $secrets->read_kubeconfig;
    unless ($kc_content) {
        $out->{error} = 'Cannot decrypt kubeconfig.yaml (is .ocp/age.key present?)';
        print STDERR "ERROR: $out->{error}\n";
        return 1;
    }

    my $k8s   = OCP::Kubernetes->new(kubeconfig => $kc_content);
    my $nodes = eval { $k8s->list_nodes };
    if (!$nodes || $@) {
        my $error = $@ || 'Unknown Kubernetes API error';
        chomp $error;
        $out->{error} = 'Cannot connect to cluster API: ' . $error;
        print STDERR "WARNING: $out->{error}\n";
        return 1;
    }

    $out->{nodes} = [ sort { $a->{name} cmp $b->{name} } map {
        +{
            name        => $k8s->node_name($_),
            ready       => ($k8s->node_ready($_) ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
            roles       => $k8s->node_roles($_),
            version     => $k8s->node_version($_),
            internal_ip => $k8s->node_internal_ip($_),
            gpu         => ($k8s->node_gpu_count($_) // 0) + 0,
        }
    } @$nodes ];

    my $drift = eval {
        OCP::Drift->new(
            config     => $config,
            api        => $k8s->api,
            rex_prober => $self->rex_prober($config),
        )->detect;
    } // [];

    $out->{drift} = [ sort { $a->{component} cmp $b->{component} || $a->{message} cmp $b->{message} } map {
        +{
            kind        => $_->{kind},
            component   => $_->{component} // $_->{label} // '',
            expected    => $_->{expected},
            actual      => $_->{actual},
            message     => $_->{message} // '',
            manual_step => $_->{manual_step},
            fixable     => ($_->{remedy} ? JSON::MaybeXS::true() : JSON::MaybeXS::false()),
        }
    } @$drift ];

    return 0;
}

1;

__END__

=synopsis

    ocp status

=description

C<ocp status> is the read-only inspection command for a project.  It prints
the spec summary (cluster name, distribution + pinned version, control planes,
worker pools) from C<ocp.yaml> and, when the cluster has been deployed, the
live state from the Kubernetes API: node name, Ready/NotReady, role labels,
kubelet version, InternalIP, GPU capacity and any L<OCP::Drift> entries that
the spec or version manifest disagree with.

If C<ocp.yaml> is missing the command dies with a hint to run C<ocp init>.
If the cluster has never been deployed the spec section is printed and the
status section says so.  The kubeconfig is read through L<OCP::Secrets>, so
the C<.ocp/age.key> must be present for the live-status section to render.

The command never modifies cluster state.  Drift entries that carry a
C<remedy> are listed together with the count that C<ocp apply> would resolve.

=head1 JSON OUTPUT

C<ocp status --json> prints exactly one JSON object (canonical: sorted keys,
pretty-printed, no timestamps or ages) on STDOUT; diagnostics go to STDERR.
Two runs against an unchanged cluster print identical bytes, so a script can
compare them.  The exit code is that of the text form: 1 when the kubeconfig
cannot be decrypted or the API cannot be reached (the object then carries an
C<error> string and whatever could be collected), else 0.

    {
       "cluster" : "mycluster",
       "config" : "ocp.yaml",
       "deployed" : true,
       "drift" : [
          {
             "actual" : "v1.32.0+rke2r1",
             "component" : "rke2",
             "expected" : "v1.32.1+rke2r1",
             "fixable" : false,
             "kind" : "version",
             "manual_step" : null,
             "message" : "rke2: ..."
          }
       ],
       "nodes" : [
          {
             "gpu" : 0,
             "internal_ip" : "10.0.0.10",
             "name" : "police1",
             "ready" : true,
             "roles" : "control-plane",
             "version" : "v1.32.1+rke2r1"
          }
       ],
       "spec" : {
          "control_planes" : { "count" : 1, "provider" : "hetzner", "server_type" : "cx32" },
          "distribution" : "rke2",
          "version" : "v1.32.1+rke2r1",
          "workers" : [ { "name" : "pool-a", "nodes" : 2, "provider" : "ssh" } ]
       }
    }

C<nodes> are sorted by name, C<drift> by component and message; a drift
entry's C<fixable> says whether C<ocp apply> carries a remedy for it.  The
drift list includes the C<< kind => 'error' >> entry that
L<OCP::Drift> reports when the API call behind a check failed.

=method execute

    $cmd->execute($args, $chain)

Prints the spec summary, then — when the cluster is deployed — the live
node table, GPU nodes and drift entries.  Returns 0 on success, 1 when the
kubeconfig could not be decrypted or the API could not be reached.

=seealso

L<OCP::Cmd::Apply>, L<OCP::Cmd::Destroy>, L<OCP::Config>,
L<OCP::Drift>, L<OCP::Kubernetes>, L<OCP::Secrets>, L<OCP::Versions>

=cut
