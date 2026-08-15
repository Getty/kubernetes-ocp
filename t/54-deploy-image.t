#!/usr/bin/env perl
# Tests for OCP::Cmd::DeployImage -- the ocp deploy-image subcommand.
#
# Network-free: Kubernetes::REST is driven with an inline transport
# (passed via `io => $t`); no socket ever opens. Secrets are bypassed by
# stubbing _build_api.

use strict;
use warnings;
use Test::More;

use JSON::MaybeXS ();
use Path::Tiny   ();

use lib 'lib';

use Kubernetes::REST ();
use OCP::K8s ();
use OCP::Cmd::DeployImage ();

# Centralised JSON encoder; matches the house rule (canonical, utf8).
our $JSON = JSON::MaybeXS->new(
    utf8            => 1,
    canonical       => 1,
    convert_blessed => 1,
);

# --- Helpers --------------------------------------------------------------

# Minimal stand-in for the OCP root singleton: only OCP::Role::Cmd's `ocp`
# method is exercised, and that reads ->command_chain->[0]->config.
package FakeOCP {
    sub new    { my ($c, %a) = @_; bless { %a }, $c }
    sub config  { $_[0]->{config} }
    sub verbose { 0 }
}

# A Kubernetes::REST-compatible transport. Records every call, returns
# whatever the `respond` callback says.
package FakeTransport {
    sub new {
        my ($c, %a) = @_;
        bless { requests => [], respond => $a{respond} }, $c;
    }
    sub requests { $_[0]->{requests} }
    sub call {
        my ($self, $req) = @_;
        my $path = $req->url;
        $path =~ s{^https?://[^/]+}{};
        push @{ $self->{requests} }, {
            method => $req->method,
            path   => $path,
            body   => $req->content,
        };
        my ($status, $body) = $self->{respond}->($req->method, $path, $req->content);
        return FakeResp->new(
            status  => $status,
            content => $JSON->encode($body),
        );
    }
}

# Bare-bones HTTP response stand-in -- Kubernetes::REST only needs
# status + content for PATCH/GET.
package FakeResp {
    sub new    { my ($c, %a) = @_; bless { %a }, $c }
    sub status  { $_[0]{status} }
    sub content { $_[0]{content} }
    sub headers { {} }
}

package main;

# Build a fake project dir + cluster name. Caller can add extra YAML
# (e.g. multi-cluster) via extra_yaml.
sub make_project {
    my (%opts) = @_;
    my $dir = Path::Tiny->tempdir;
    my $name = $opts{cluster_name} // 'mycluster';
    my $yaml = "name: $name\n";
    $yaml .= $opts{extra_yaml} if defined $opts{extra_yaml};
    $dir->child('ocp.yaml')->spew_utf8($yaml);
    return $dir;
}

# Build a Kubernetes::REST with the fake transport + registered CRDs.
sub make_api {
    my ($transport) = @_;
    my $api = Kubernetes::REST->new(
        server                    => { endpoint => 'https://cluster.invalid:6443' },
        credentials               => { token => 'fake-token' },
        io                        => $transport,
        resource_map_from_cluster => 0,
    );
    OCP::K8s->register($api);
    return $api;
}

# Run the command under controlled conditions. Returns a result hash with
# result (exit code), error (eval $@), transport (request log), output.
sub run_cmd {
    my (%opts) = @_;
    my $dir       = $opts{dir}       // make_project();
    my $respond   = $opts{respond}   // sub { (404, { message => 'unexpected' }) };
    my $transport = FakeTransport->new(respond => $respond);

    my $api = make_api($transport);
    my $fake_ocp = FakeOCP->new(config => "$dir/ocp.yaml");

    # MooX::Options attributes are constructor params; _poll_interval keeps
    # the wait-loop instant in tests.
    my %ctor = (
        _poll_interval => 0,
        command_chain  => [$fake_ocp],
    );
    $ctor{image}     = $opts{image}     if defined $opts{image};
    $ctor{tag}       = $opts{tag}       if defined $opts{tag};
    $ctor{cluster}   = $opts{cluster}   if defined $opts{cluster};
    $ctor{namespace} = $opts{namespace} if defined $opts{namespace};
    $ctor{repo}      = $opts{repo}      if defined $opts{repo};
    $ctor{wait}      = $opts{wait}      if $opts{wait};
    $ctor{timeout}   = $opts{timeout}   if defined $opts{timeout};
    $ctor{restart}   = $opts{restart}   if exists $opts{restart};

    my $cmd = OCP::Cmd::DeployImage->new(%ctor);

    # Bypass OCP::Secrets + kubeconfig loading.
    no warnings 'redefine';
    local *OCP::Cmd::DeployImage::_build_api = sub { return $api };

    my $output = '';
    open my $out_fh, '>', \$output or die $!;
    local *STDOUT = $out_fh;

    my $result = eval { $cmd->execute(undef, []) };

    return {
        cmd       => $cmd,
        transport => $transport,
        result    => $result,
        error     => $@,
        output    => $output,
    };
}

# A fully-formed Deployment object as the fake cluster would return it.
sub deployment {
    my (%over) = @_;
    return {
        apiVersion => 'apps/v1',
        kind       => 'Deployment',
        metadata   => {
            name       => 'robocop',
            namespace  => $over{namespace} // 'ocp-system',
            generation => $over{generation} // 1,
        },
        spec => {
            replicas => 1,
            selector => { matchLabels => { app => 'robocop' } },
            template => {
                metadata => { labels => { app => 'robocop' } },
                spec     => {
                    containers => [
                        { name => 'controller', image => 'raudssus/ocp:latest' },
                    ],
                },
            },
        },
        status => {
            availableReplicas  => $over{availableReplicas}  // 1,
            readyReplicas      => $over{readyReplicas}      // 1,
            replicas           => $over{replicas}           // 1,
            observedGeneration => $over{observedGeneration} // $over{generation} // 1,
        },
        %over,
    };
}

sub deployment_path { "/apis/apps/v1/namespaces/$_[0]/deployments/robocop" }

# --- Tests ----------------------------------------------------------------

subtest 'happy path: --tag v1.2.3 patches image and triggers restart' => sub {
    my $r = run_cmd(
        tag => 'v1.2.3',
        respond => sub {
            my ($m, $p) = @_;
            return (200, deployment()) if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    is($r->{result}, 0, 'returns 0 on success');

    my @patches = grep { $_->{method} eq 'PATCH' } @{ $r->{transport}->requests };
    is(scalar @patches, 2, 'two patches issued: image + restart');

    my ($img) = grep { $_->{body} =~ /raudssus\/ocp:v1\.2\.3/ } @patches;
    ok($img, 'image patch contains the new image tag');
    like($img->{body}, qr/"name"\s*:\s*"controller"/,
         'and addresses the controller container by name');
    like($img->{body}, qr/"image"\s*:\s*"raudssus\/ocp:v1\.2\.3"/,
         'and sets the image field');

    my ($restart) = grep { $_->{body} =~ /restartedAt/ } @patches;
    ok($restart, 'restart patch contains the restartedAt annotation');
    like($restart->{body}, qr/"kubectl\.kubernetes\.io\/restartedAt"/,
         'and addresses the canonical annotation key');
};

subtest '--no_restart skips the rollout restart' => sub {
    my $r = run_cmd(
        tag     => 'v1.2.3',
        restart => 0,
        respond => sub {
            my ($m, $p) = @_;
            return (200, deployment()) if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');

    my @patches = grep { $_->{method} eq 'PATCH' } @{ $r->{transport}->requests };
    is(scalar @patches, 1, 'exactly one patch: image only');
    ok((grep { /raudssus\/ocp:v1\.2\.3/ } map { $_->{body} } @patches), 'and it is the image patch');
    ok(!(grep { /restartedAt/ } map { $_->{body} } @patches), 'no restart annotation was written');
};

subtest '--wait returns 0 once deployment reports Ready' => sub {
    my $polls = 0;
    my $r = run_cmd(
        tag     => 'v1.2.3',
        wait    => 1,
        timeout => 30,
        respond => sub {
            my ($m, $p) = @_;
            if ($m eq 'GET' && $p eq deployment_path('ocp-system')) {
                $polls++;
                # First poll: not yet ready. Second poll: caught up.
                if ($polls == 1) {
                    return (200, deployment(
                        availableReplicas  => 0,
                        observedGeneration => 1,
                        generation         => 1,
                    ));
                }
                return (200, deployment());
            }
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    is($r->{result}, 0, 'returns 0 when pods become Ready');
    ok($polls >= 2, 'polled the deployment status more than once');
    like($r->{output}, qr/Ready/, 'reports Ready in stdout');
};

subtest '--wait --timeout 1 times out when pods never become Ready' => sub {
    my $r = run_cmd(
        tag     => 'v1.2.3',
        wait    => 1,
        timeout => 1,
        respond => sub {
            my ($m, $p) = @_;
            if ($m eq 'GET' && $p eq deployment_path('ocp-system')) {
                # observedGeneration < generation: status is stale, never Ready.
                return (200, deployment(
                    availableReplicas  => 0,
                    observedGeneration => 1,
                    generation         => 2,
                ));
            }
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    is($r->{result}, 1, 'returns 1 on timeout');
};

subtest 'missing deployment: fail loud with hint to deploy-robocop' => sub {
    my $r = run_cmd(
        tag => 'v1.2.3',
        respond => sub {
            my ($m, $p) = @_;
            return (404, { message => 'not found' })
                if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (404, { message => "unexpected $m $p" });
        },
    );

    ok($r->{error}, 'execute dies when deployment is missing');
    like($r->{error}, qr/robocop Deployment not found/,
         'with a message naming the resource');
    like($r->{error}, qr/ocp-system/, 'and the namespace');
    like($r->{error}, qr/deploy-robocop/, 'and hints to run ocp deploy-robocop first');
};

subtest '--cluster mismatch with OCP_CLUSTER fails loud' => sub {
    local $ENV{OCP_CLUSTER} = 'production';

    my $r = run_cmd(
        tag     => 'v1.2.3',
        cluster => 'staging',
    );

    ok($r->{error}, 'execute dies on cluster mismatch');
    like($r->{error}, qr/contradicts|mismatch|production|staging/i,
         'mentions both clusters');
};

subtest 'multi-cluster spec without --cluster fails loud with names listed' => sub {
    my $dir = make_project(
        extra_yaml => "clusters:\n  - name: alpha\n  - name: beta\n",
    );
    my $r = run_cmd(tag => 'v1.2.3', dir => $dir);

    ok($r->{error}, 'execute dies with multi-cluster spec');
    like($r->{error}, qr/multiple clusters/i, 'mentions multi-cluster detection');
    like($r->{error}, qr/alpha/, 'lists alpha');
    like($r->{error}, qr/beta/,  'lists beta');
};

subtest '--repo overrides the default image repository' => sub {
    my $r = run_cmd(
        tag  => 'v1.2.3',
        repo => 'my-registry.example/ocp',
        respond => sub {
            my ($m, $p) = @_;
            return (200, deployment()) if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    my @bodies = map { $_->{body} } grep { $_->{method} eq 'PATCH' } @{ $r->{transport}->requests };
    ok((grep { /my-registry\.example\/ocp:v1\.2\.3/ } @bodies),
       'image prefix is overridden by --repo');
    ok(!(grep { /raudssus\/ocp:v1\.2\.3/ } @bodies),
       'default prefix is not used');
};

subtest 'OCP_IMAGE_REPO env var overrides the default' => sub {
    local $ENV{OCP_IMAGE_REPO} = 'env-registry.example/ocp';

    my $r = run_cmd(
        tag => 'v1.2.3',
        respond => sub {
            my ($m, $p) = @_;
            return (200, deployment()) if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    my @bodies = map { $_->{body} } grep { $_->{method} eq 'PATCH' } @{ $r->{transport}->requests };
    ok((grep { /env-registry\.example\/ocp:v1\.2\.3/ } @bodies),
       'env var is used for the image prefix');
};

subtest '--namespace is respected for every request' => sub {
    my $r = run_cmd(
        tag       => 'v1.2.3',
        namespace => 'custom-ns',
        respond   => sub {
            my ($m, $p) = @_;
            return (200, deployment(namespace => 'custom-ns'))
                if $m eq 'GET' && $p eq deployment_path('custom-ns');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    my @reqs = @{ $r->{transport}->requests };
    ok((grep { $_->{path} eq deployment_path('custom-ns') } @reqs),
       'all requests address the custom namespace');
    ok(!(grep { $_->{path} =~ /ocp-system/ } @reqs),
       'and none address the default namespace');
};

subtest '--timeout without --wait fails loud' => sub {
    my $r = run_cmd(
        tag     => 'v1.2.3',
        timeout => 60,
        respond => sub { (200, deployment()) },
    );

    ok($r->{error}, 'execute dies');
    like($r->{error}, qr/--timeout.*--wait/i, 'mentions the constraint');
};

subtest 'missing ocp.yaml fails loud with init hint' => sub {
    my $dir = Path::Tiny->tempdir;   # no ocp.yaml
    my $r = run_cmd(dir => $dir);

    ok($r->{error}, 'execute dies');
    like($r->{error}, qr/init/i, 'mentions ocp init');
};

# --- --image shorthand -----------------------------------------------------
#
# _parse_image_ref is a pure function -- we call it as a class method so we
# don't need a full instance just to test the parser. The same sub feeds
# execute() at runtime via $self->_parse_image_ref($self->image), so the
# dispatch is symmetric and one definition covers both call sites.

subtest '_parse_image_ref: registry/repo:tag (tag form)' => sub {
    my $r = OCP::Cmd::DeployImage->_parse_image_ref('ghcr.io/foo/bar:v1.2.3');
    is($r->{repo}, 'ghcr.io/foo/bar', 'repo contains the registry prefix');
    is($r->{tag},  'v1.2.3',          'tag extracted exactly');
    ok(!exists $r->{digest}, 'no digest in the result');
};

subtest '_parse_image_ref: foo/bar:tag (Docker Hub implicit)' => sub {
    my $r = OCP::Cmd::DeployImage->_parse_image_ref('foo/bar:v1.2.3');
    is($r->{repo}, 'foo/bar', 'repo is bare two-segment path');
    is($r->{tag},  'v1.2.3',  'tag extracted');
};

subtest '_parse_image_ref: foo/bar@sha256:<64hex> (digest form)' => sub {
    my $digest = 'sha256:' . ('a' x 64);
    my $r      = OCP::Cmd::DeployImage->_parse_image_ref("foo/bar\@$digest");
    is($r->{repo},   'foo/bar', 'repo extracted');
    is($r->{digest}, $digest,   'digest preserved exactly');
    ok(!exists $r->{tag}, 'no tag in the result');
};

subtest '_parse_image_ref: no tag and no digest -> fail (no implicit latest)' => sub {
    eval { OCP::Cmd::DeployImage->_parse_image_ref('ghcr.io/foo/bar') };
    ok($@, 'dies loud on bare repo');
    like($@, qr/(?i)tag|latest/, 'message names the missing pin');
};

subtest '_parse_image_ref: empty digest after @ -> fail' => sub {
    eval { OCP::Cmd::DeployImage->_parse_image_ref('foo/bar@') };
    ok($@, 'dies loud on empty digest');
    like($@, qr/digest|invalid/i, 'message names the digest format');
};

subtest '_parse_image_ref: sha256 with wrong hex length -> fail' => sub {
    eval { OCP::Cmd::DeployImage->_parse_image_ref('foo/bar@sha256:abc') };
    ok($@, 'dies loud on short hex');
    like($@, qr/digest.*format/i, 'message names the digest format');
};

subtest '_parse_image_ref: empty string -> fail' => sub {
    eval { OCP::Cmd::DeployImage->_parse_image_ref('') };
    ok($@, 'dies loud on empty input');
    like($@, qr/empty/i, 'message names the empty input');
};

subtest '_parse_image_ref: tag with slashes + no registry -> fail with hint' => sub {
    eval { OCP::Cmd::DeployImage->_parse_image_ref('foo/bar:baz/qux') };
    ok($@, 'dies loud on tag-with-slashes + bare repo');
    like($@, qr/(?i)ambig|registry/, 'message hints at the registry prefix');
};

subtest '--image and --tag are mutually exclusive (fail loud)' => sub {
    my $r = run_cmd(
        image => 'ghcr.io/foo/bar:v1.2.3',
        tag   => 'v9.9.9',
    );
    ok($r->{error}, 'execute dies when both --image and --tag are given');
    like($r->{error}, qr/--image.*--tag/i, 'names both flags in the conflict');
    like($r->{error}, qr/mutually exclusive/i, 'explains the constraint');
};

subtest '--image and --repo are mutually exclusive (fail loud)' => sub {
    my $r = run_cmd(
        image => 'ghcr.io/foo/bar:v1.2.3',
        repo  => 'my-registry.example/ocp',
    );
    ok($r->{error}, 'execute dies when both --image and --repo are given');
    like($r->{error}, qr/--image.*--repo/i, 'names both flags in the conflict');
};

subtest '--image ghcr.io/foo/bar:v1.2.3 patches that exact string' => sub {
    my $r = run_cmd(
        image => 'ghcr.io/foo/bar:v1.2.3',
        respond => sub {
            my ($m, $p) = @_;
            return (200, deployment()) if $m eq 'GET' && $p eq deployment_path('ocp-system');
            return (200, {}) if $m eq 'PATCH';
            return (404, { message => "unexpected $m $p" });
        },
    );

    is($r->{error}, '', 'execute did not die');
    is($r->{result}, 0, 'returns 0 on success');

    my @bodies = map { $_->{body} } grep { $_->{method} eq 'PATCH' } @{ $r->{transport}->requests };
    ok((grep { /"image"\s*:\s*"ghcr\.io\/foo\/bar:v1\.2\.3"/ } @bodies),
       'image field set to the full reference');
    ok((grep { /"image"\s*:\s*"raudssus\/ocp:v1\.2\.3"/ } @bodies) == 0,
       'default repo is NOT used when --image is given');
};

# Both booleans were declared `is_bool => 1`, which MooX::Options does not
# know: the key went straight through to `has` and was ignored, so no `!`
# reached the option spec. `--no-wait` died with "Unknown option: no_wait",
# and --no_restart — the spelling the POD, the doc string and the runtime
# message all advertised — had no working form at all, leaving --restart
# with no way to be switched off from the command line. Every subtest above
# sets restart/wait on the constructor, which is why none of them noticed.
#
# new_with_options runs the real MooX::Options parse over the real spec
# without MooX::Cmd's execute, so this stays in-process and network-free.
subtest 'the boolean flags parse from the command line, both ways' => sub {
    my $parse = sub {
        local @ARGV = @_;
        return OCP::Cmd::DeployImage->new_with_options;
    };

    my $plain = $parse->(qw(--tag v1.2.3));
    ok(!$plain->wait,   'waiting is still off unless asked');
    is($plain->restart, 1, 'restarting is still on by default');

    is($parse->(qw(--tag v1.2.3 --wait))->wait, 1, '--wait turns waiting on');
    for my $spelling (qw(--no-wait --nowait)) {
        my $cmd = $parse->('--tag', 'v1.2.3', $spelling);
        is($cmd->wait, 0, "$spelling turns waiting off instead of dying");
    }

    is($parse->(qw(--tag v1.2.3 --restart))->restart, 1, '--restart keeps it on');
    for my $spelling (qw(--no-restart --norestart)) {
        my $cmd = $parse->('--tag', 'v1.2.3', $spelling);
        is($cmd->restart, 0, "$spelling actually reaches the attribute");
    }
};

done_testing;
