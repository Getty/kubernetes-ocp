#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Cmd::Destroy;
use OCP::Config;

#
# karr #116: `ocp destroy` left the local-provider node running. Two halves of
# the same drop -- both are missed by `eq 'ssh'`:
#
#   1. The fallback node list (no .ocp/status.yaml) hard-coded
#      `$cp->{provider} // 'ssh'` and `$w->{provider} eq 'ssh'`, so a worker
#      pool or CP carrying `provider: local` was either relabelled or skipped
#      before the delete loop even saw it.
#
#   2. The delete dispatch itself only knew about `hetzner` and `ssh`. A node
#      that DID make the list (because a real `ocp apply` wrote status.yaml)
#      hit the elsif, fell through with nothing, and "Cluster destroyed." was
#      printed while the local machine kept running and kept costing.
#
# Both are reproduced here, then locked against by a regression subtest that
# fails if the literals come back.
#

# ---------------------------------------------------------------- stubs

# The root command. `ocp destroy` reads its ocp.yaml path off `config`
# exactly the way the other commands do, so this is the seam.
{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# Records the calls OCP::Provider would have made. The real adapters are
# stubbed for the same reason t/29 and t/71 stub them: this test is about
# what `ocp destroy` decided to call, not about how OCP::Provider::Local
# actually uninstalls RKE2 on 127.0.0.1 (t/50 covers that).
{
    package FakeProvider;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        push @{ $self->{deleted} }, {
            type => $self->{type},
            id   => $id,
            host => $opts{host},
        };
        return { stdout => '', stderr => '', exit => 0 };
    }
}

# Project fixture. The default shape is provider: local in control_planes;
# workers/status are optional to cover the fallback-vs-status distinction.
sub project {
    my (%args) = @_;

    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;

    my $yaml = <<'YAML';
name: localtest
control_planes:
  provider: local
  host: 127.0.0.1
YAML

    if ($args{workers}) {
        $yaml .= <<'YAML';

workers:
  - name: local-pool
    provider: local
    nodes:
      - 127.0.0.1
YAML
    }

    $dir->child('ocp.yaml')->spew_utf8($yaml);

    if ($args{status}) {
        $dir->child('.ocp', 'status.yaml')->spew_utf8($args{status});
    }

    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config) = @_;

    my @deleted;
    my $destroy = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,
    );

    # Capture STDOUT while running. STDERR leaks via $@ separately; both
    # come back so a dieing provider or a dying dispatch is unambiguous.
    my $out = '';
    open my $fh, '>', \$out or die "capture: $!";
    my $old = select $fh;
    my @r = eval {
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec, %args) = @_;
            return FakeProvider->new(
                type    => $spec->{provider},
                deleted => \@deleted,
            );
        };
        # Local has no token to ask for; an empty key still makes the lookup
        # deterministic so the test never trips on a missing secrets.yaml.
        local *OCP::Secrets::hetzner_token = sub { undef };
        $destroy->execute([], []);
    };
    my $err = $@;
    select $old;
    close $fh;

    return { out => $out, err => $err, deleted => \@deleted };
}

# ------------------------------------------------------------- regression

subtest 'status.yaml path: a recorded local node reaches the local provider' => sub {
    # The common shape: a real `ocp apply` writes status.yaml with the local
    # CP. The delete loop's `elsif ($node->{provider} eq 'ssh')` branch never
    # matched `local`, so the node was silently skipped while the teardown
    # announced success.
    my $config = project(status => <<'YAML');
nodes:
  - name: cp-1
    provider: local
    public_ip: 127.0.0.1
YAML

    my $r = run_destroy($config);
    is $r->{err}, '', 'ran clean' or diag $r->{out};

    my ($local) = grep { $_->{type} eq 'local' } @{ $r->{deleted} };
    ok $local, 'delete_server was called through the local provider';
    is $local->{host}, '127.0.0.1',
        'against the host recorded in status.yaml';
};

subtest 'fallback path: a local CP is not relabelled ssh and is added to the list' => sub {
    # No status.yaml, so the loop falls back to spec. The hard-coded
    # `$cp->{provider} // 'ssh'` literal was a relabel, not just a default --
    # any local CP became 'ssh' on the reconstructed node, and the ssh
    # branch then had no key to look up and skipped.
    my $config = project();

    my $r = run_destroy($config);
    is $r->{err}, '', 'ran clean' or diag $r->{out};

    like $r->{out}, qr/127\.0\.0\.1 \(local,/,
        'the CP is announced as local, not relabelled ssh';
    ok !(grep { $_->{type} eq 'ssh' } @{ $r->{deleted} }),
        'no ssh provider was asked to do anything';

    my ($local) = grep { $_->{type} eq 'local' } @{ $r->{deleted} };
    ok $local, 'the local provider was asked to delete the node';
    is $local->{host}, '127.0.0.1',
        'against the host recorded in ocp.yaml';
};

subtest 'fallback path: a local worker pool reaches the delete loop' => sub {
    # The literal `$w->{provider} eq 'ssh'` gate on the worker fallback
    # dropped this pool wholesale. The pool wasn't even in the destruction
    # list, so there was nothing for the loop to skip.
    my $config = project(workers => 1);

    my $r = run_destroy($config);
    is $r->{err}, '', 'ran clean' or diag $r->{out};

    like $r->{out}, qr/127\.0\.0\.1 \(local,/,
        'the local worker is named in the destruction plan';
    ok !(grep { $_->{type} eq 'ssh' } @{ $r->{deleted} }),
        'no ssh provider was asked to do anything';

    my ($local) = grep { $_->{type} eq 'local' } @{ $r->{deleted} };
    ok $local, 'the worker pool was destroyed through the local provider';
};

subtest 'delete dispatch: local and ssh share the same role and the same branch' => sub {
    # The loop has one branch for clouds (Hetzner) and one for existing-host
    # providers (ssh, local). Before karr #116 the second branch literally
    # checked for 'ssh', so 'local' silently fell through -- the same way a
    # future provider type would silently fall through today.
    my $src = path('lib/OCP/Cmd/Destroy.pm')->slurp;

    # We anchor on the elsif that selects the existing-host branch. The
    # four remaining `eq 'ssh'` checks in the body are correct -- ssh really
    # IS the only provider that needs the cluster key, the migration hint,
    # or the ssh_key_path handed to for_spec -- and rewriting them to handle
    # local too would either over-prompt for a PIN2 the local run never
    # needed, or hide a key. The dispatch gate is what mattered.
    unlike $src, qr/elsif\s+\(\s*\$node->\{provider\}\s+eq\s+(['"])ssh\1/,
        'the per-node dispatch no longer gates on `$node->{provider} eq ssh`';

    like $src, qr/elsif\s+\([^)]*known_type\(\s*\$node->\{provider\}/s,
        'and now dispatches through known_type($node->{provider}), reading the type list once';
};

subtest 'regression: the gate is known_type(), not an eq on the literal' => sub {
    # Same shape karr #103 used in six other places. If anyone re-hardcodes
    # the `eq 'ssh'` form here, the next provider type OCP adds (the only
    # list in OCP::Provider->types) will be silently dropped again.
    my $src = path('lib/OCP/Cmd/Destroy.pm')->slurp;

    unlike $src, qr/\$w->\{provider\}\s+eq\s+(['"])ssh\1/,
        'no `$w->{provider} eq ssh` survives anywhere in Destroy.pm';
    unlike $src, qr/\$cp->\{provider\}\s+\/\/\s+(['"])ssh\1/,
        'no `$cp->{provider} // ssh` survives anywhere in Destroy.pm';

    like $src, qr/known_type\(\s*\$cp->\{provider\}/,
        'and the CP fallback gates on known_type, reading the type list once';
    like $src, qr/known_type\(\s*\$w->\{provider\}/,
        'and so does the worker fallback';
};

done_testing;
