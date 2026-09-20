#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw(path);

use lib 'lib';

#
# A `local` control plane gets no OCPNodeProvider CR from `ocp apply` — k151.
#
# `ocp apply` with control_planes.provider: local deployed the control plane
# fine (RKE2, Cilium, registry, NFD, cert-manager, Node Ready) and then aborted
# with exit 1 in "Step 3: Ensure CRDs and provider CRs":
#
#   Error: Kubernetes API error (create OCP::K8s::OCPNodeProvider): 422
#   OCPNodeProvider.ocp.internal "local-default" is invalid:
#   spec.type: Unsupported value: "local": supported values: "hetzner", "ssh"
#
# ensure_provider_cr wrote a `local-default` OCPNodeProvider for the local CP,
# and a cluster whose CRD enum predates `local` (k110) rejected it. Because the
# worker-reconcile phase and the status.ocpVersion stamp both run AFTER Step 3,
# the abort meant no worker could ever join a local-CP cluster and the cluster
# never reported a deployed version.
#
# A local control plane is observational: it is bootstrapped in place, its
# OCPNode status is written directly by ensure_cp_ocpnode, and there is no local
# provider *controller* that would ever read a local-default provider CR back.
# So the fix is that ensure_provider_cr skips the write for a local provider,
# while hetzner and ssh keep their <type>-default CR exactly as before.
#
# This asserts two things:
#   1. ensure_provider_cr('local', ...) writes nothing at all.
#   2. ensure_providers over a local CP + ssh workers writes the ssh provider
#      CR but no local one, AND survives an API that rejects `type: local` the
#      way the cluster in the bug report did — i.e. Step 3 no longer aborts, so
#      the worker phase and version stamp downstream stay reachable.
#

# Records every ensure() call. The writer end of the seam, exactly as t/74 uses
# it against ensure_provider_cr.
package RecordingApi {
    sub new { my ($c) = @_; bless { ensured => [] }, $c }
    sub ensure {
        my ($self, $doc) = @_;
        push @{ $self->{ensured} }, $doc;
        return $doc;
    }
    sub providers_of_type {
        my ($self, $type) = @_;
        return grep {
            ($_->{kind} // '') eq 'OCPNodeProvider'
                && ($_->{spec}{type} // '') eq $type
        } @{ $self->{ensured} };
    }
    sub named {
        my ($self, $name) = @_;
        return grep { ($_->{metadata}{name} // '') eq $name } @{ $self->{ensured} };
    }
}

# The same recorder, but its ensure() refuses an OCPNodeProvider whose spec.type
# is not in the CRD enum the field cluster had (hetzner, ssh) — reproducing the
# 422 that aborted Step 3. A local CR must never reach it.
package ValidatingApi {
    use Carp qw(croak);
    my %ALLOWED = (hetzner => 1, ssh => 1);
    sub new { my ($c) = @_; bless { ensured => [] }, $c }
    sub ensure {
        my ($self, $doc) = @_;
        if (($doc->{kind} // '') eq 'OCPNodeProvider') {
            my $type = $doc->{spec}{type} // '';
            croak "Kubernetes API error (create OCP::K8s::OCPNodeProvider): 422 "
                . "spec.type: Unsupported value: \"$type\": supported values: "
                . '"hetzner", "ssh"'
                unless $ALLOWED{$type};
        }
        push @{ $self->{ensured} }, $doc;
        return $doc;
    }
    sub providers_of_type {
        my ($self, $type) = @_;
        return grep {
            ($_->{kind} // '') eq 'OCPNodeProvider'
                && ($_->{spec}{type} // '') eq $type
        } @{ $self->{ensured} };
    }
}

# ensure_provider_cr's ssh path reads nothing off secrets (only the hetzner
# branch does). If it ever asks for the token on a local+ssh cluster, that is a
# bug, so this croaks rather than answering.
package FakeSecrets {
    use Carp qw(croak);
    sub new { my ($c) = @_; bless {}, $c }
    sub hetzner_token { croak "hetzner_token must not be read on a local+ssh cluster" }
}

package main;

use OCP::Cmd::Apply::CR;
use OCP::Config;

# A real project on disk: a local control plane with an ssh worker pool — the
# combination the ticket's DONE criteria name (ssh workers joinable on a
# local-CP cluster).
my $tmp = Path::Tiny->tempdir;
$tmp->child('.ocp')->mkpath;
$tmp->child('ocp.yaml')->spew(<<'YAML');
name: cihq
control_planes:
  - provider: local
workers:
  - name: pool-a
    provider: ssh
    host: worker1.example
YAML

my $config = OCP::Config->new(file => $tmp->child('ocp.yaml')->stringify);
is $config->name, 'cihq', 'config carries the cluster name';

# Capture STDOUT so the [skip] progress line does not muddy the test output.
sub silence_stdout {
    my ($code) = @_;
    my $out = '';
    open my $ofh, '>', \$out or die "capture: $!";
    my $old = select $ofh;
    my @r = eval { $code->() };
    my $err = $@;
    select $old;
    close $ofh;
    die $err if $err;
    return ($out, @r);
}

#
# 1. ensure_provider_cr for a local provider writes nothing.
#
subtest 'ensure_provider_cr(local) writes no CR at all' => sub {
    my $rec = RecordingApi->new;
    my ($out) = silence_stdout(sub {
        OCP::Cmd::Apply::CR::ensure_provider_cr(
            undef, $rec, 'local', 'ocp-system', $config, FakeSecrets->new,
        );
    });
    is scalar(@{ $rec->{ensured} }), 0,
        'nothing is ensured for a local provider — no OCPNodeProvider, no Secret';
    is scalar($rec->providers_of_type('local')), 0,
        'and in particular no OCPNodeProvider of type local';
    like $out, qr/skip/, 'the progress narrative says it was skipped, not silently dropped';
};

#
# 2. ensure_providers over the whole spec: the ssh provider is written, the
#    local one is not, and an API that rejects type: local does not abort.
#
subtest 'ensure_providers skips local, keeps ssh, and does not abort on a strict CRD' => sub {
    my $api = ValidatingApi->new;

    # ensure_providers is a plain function: ($self, $api, $config, $secrets).
    # $self is unused, so undef is honest here.
    my $ok = eval {
        silence_stdout(sub {
            OCP::Cmd::Apply::CR::ensure_providers(undef, $api, $config, FakeSecrets->new);
        });
        1;
    };
    ok $ok, 'Step 3 runs to completion — no 422 abort before the worker phase'
        or diag "ensure_providers died: $@";

    is scalar($api->providers_of_type('local')), 0,
        'no local OCPNodeProvider was ever sent to the API';

    my @ssh = $api->providers_of_type('ssh');
    is scalar(@ssh), 1, 'the ssh worker pool still gets its OCPNodeProvider';
    is $ssh[0]{metadata}{name}, 'ssh-default',
        'named ssh-default, the name from_cr and destroy depend on';
    is $ssh[0]{spec}{clusterName}, 'cihq',
        'and it still carries spec.clusterName so servers stay findable';
};

done_testing;
