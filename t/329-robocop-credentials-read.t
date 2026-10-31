#!/usr/bin/env perl
# karr k329 -- a robocop-credentials Secret that cannot be read is not missing.
#
# _robocop_credentials_state read the Secret as `eval { get } or 'missing'`:
# an RBAC denial, an apiserver 5xx or a broken connection said "there is no
# Secret". The dry run then announced a write it could not know was due, a
# real run went for that write -- the age key, a PIN2 prompt, the SSH read of
# the join token -- over a Secret it could not see, and an operator run
# (SOPS_AGE_KEY_FILE, k216) was told the Secret "does not exist". Only a 404
# is missing (the k269/k277/k319 rule). The claims:
#
#   * the state: a 404 is 'missing'; a 403, a 500 or a transport error dies
#     "could not read Secret ocp-system/robocop-credentials: <cause>"; a
#     Secret it can read is still compared ('current')
#   * ocp apply (robocop_step): on such a failure nothing is written, no PIN2
#     asked, no SSH read made; the step fails with the cause on STDERR. A 404
#     still writes the Secret and rolls robocop out
#   * an operator run is not told the Secret does not exist
#   * ocp apply --dry-run: "could not be checked" on STDOUT, the cause on
#     STDERR, an { kind => 'error' } entry -- what the dry run counts as could
#     not be checked (t/38, k319) -- instead of "missing, would write it"
#
# `ocp keys secure`'s own robocop Deployment read is pinned in t/96.
#
# Network-free and cluster-free: the K8s api is a fake that stores what is
# ensured and serves it back, and answers a read with the error queued for
# it. keys.yaml / age.key are real; the PIN prompt is stubbed on
# OCP::Password, the SSH token read on OCP::SSH::run.

use strict;
use warnings;
use Test::More;

use Kubernetes::REST::APIError;
use MIME::Base64 ();
use Path::Tiny ();

use lib 'lib';

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Deploy;
use OCP::Cmd::Apply::Drift;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Secrets;
use OCP::SSH;

local @ARGV = ();
my $ocp = OCP->new;

my $ROBO_PRIV  = "-----BEGIN OPENSSH PRIVATE KEY-----\nROBOAUTOMATIONKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $ADMIN_PRIV = "-----BEGIN OPENSSH PRIVATE KEY-----\nADMINHUMANKEY\n-----END OPENSSH PRIVATE KEY-----\n";
my $PIN2       = 'correct-horse';
my $TOKEN      = 'K10deadbeefcafe::server:0123456789abcdef';
my $CP_IP      = '10.0.0.1';
my $SECRET     = 'Secret/ocp-system/robocop-credentials';

# What Kubernetes::REST dies with for an HTTP error status (as in t/319).
sub api_error {
    my ($code, $reason) = @_;
    return Kubernetes::REST::APIError->new(
        code    => $code,
        context => 'get',
        body    => qq({"kind":"Status","apiVersion":"v1","status":"Failure","reason":"$reason","code":$code}),
    );
}

# The reads that are no verdict on the Secret: each with what its cause
# reads like in the message.
my @REFUSALS = (
    [ '403', api_error(403, 'Forbidden'),     qr/Kubernetes API error \(get\): 403 .*"reason":"Forbidden"/ ],
    [ '500', api_error(500, 'InternalError'), qr/Kubernetes API error \(get\): 500 .*"reason":"InternalError"/ ],
    [ 'transport', "Connection refused\n",    qr/Connection refused/ ],
);

# --- Fakes ----------------------------------------------------------------

package FakeList {
    sub new   { bless { items => $_[1] }, $_[0] }
    sub items { $_[0]{items} }
}

# Stores every ensured object under kind/namespace/name and serves it back, a
# Secret as the API server does (values base64-encoded under data). A read
# with an error in {refuse}{$key} dies with it.
package FakeApi {
    sub new { my ($c, %a) = @_; bless { log => [], objects => {}, refuse => {}, %a }, $c }

    sub ensure {
        my ($self, $obj) = @_;
        my $key = join '/', $obj->{kind}, $obj->{metadata}{namespace} // '-',
            $obj->{metadata}{name};
        push @{ $self->{log} }, $key;
        my %stored = %$obj;
        if ($obj->{kind} eq 'Secret' && $obj->{stringData}) {
            delete $stored{stringData};
            $stored{data} = { map {
                $_ => MIME::Base64::encode_base64($obj->{stringData}{$_}, '')
            } keys %{ $obj->{stringData} } };
        }
        $self->{objects}{$key} = \%stored;
        return $obj;
    }

    sub get {
        my ($self, $kind, $name, %opt) = @_;
        my $key = join '/', $kind, $opt{namespace} // '-', $name;
        die $self->{refuse}{$key} if $self->{refuse}{$key};
        return $self->{objects}{$key} // die Kubernetes::REST::APIError->new(
            code => 404, context => 'get',
            body => '{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}',
        );
    }

    sub list             { FakeList->new([]) }
    sub k8s              { $_[0] }
    sub object_to_struct { $_[1] }

    sub ensured { $_[0]{log} }
}

package FakeOCP {
    sub new     { bless {}, shift }
    sub verbose { 0 }
}

package main;

{
    no warnings qw( redefine once );
    *OCP::Cmd::Apply::_wait_robocop_ready = sub { 1 };
    *OCP::Cmd::Apply::wait_seconds        = sub { };
}

# A secure-mode project (keys.yaml with a robo and an admin key, a real age
# key), robocop on at security_level secret, an ssh control plane.
sub make_project {
    my $dir = Path::Tiny->tempdir;

    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k329',
        control_planes => { provider => 'ssh', host => 'police1' },
        robocop        => { enabled => 1, security_level => 'secret' },
    });

    OCP::Secrets->new(project_dir => $dir)->generate_age_key;

    my $keys = OCP::Keys->new(project_dir => $dir);
    $keys->add_key(
        name    => 'robo-ssh',
        type    => 'ssh_ed25519',
        private => $ROBO_PRIV,
        public  => 'ssh-ed25519 AAAArobo robo',
        purpose => 'automation',
    );
    $keys->add_key(
        name    => 'admin-ssh',
        type    => 'ssh_ed25519',
        private => $ADMIN_PRIV,
        public  => 'ssh-ed25519 AAAAadmin admin',
        purpose => 'admin',
        pin2    => $PIN2,
    );
    return $dir;
}

sub config_for {
    OCP::Config->new(file => $_[0]->child('ocp.yaml')->stringify, ocp => $ocp);
}

sub new_apply {
    my ($api) = @_;
    my $apply = OCP::Cmd::Apply->new(command_chain => [ FakeOCP->new ]);
    $apply->{_k8s_api} = $api;
    return $apply;
}

# The Secret a write for $config at level secret leaves, as the API server
# hands it back.
sub current_secret {
    my ($config) = @_;
    my %plain = (
        'robo-ssh-key' => $ROBO_PRIV,
        'server-url'   => $config->join_url($CP_IP),
        'rke2-token'   => $TOKEN,
    );
    return { kind => 'Secret',
             metadata => { name => 'robocop-credentials', namespace => 'ocp-system' },
             data => { map { $_ => MIME::Base64::encode_base64($plain{$_}, '') } keys %plain } };
}

# $code run with prompts and SSH recorded, STDOUT/STDERR captured.
sub run_captured {
    my ($code) = @_;
    my (@prompts, @ssh);
    my ($out, $err) = ('', '');
    my ($rv, $died);
    {
        no warnings 'redefine';
        local $OCP::ClusterKey::INTERACTIVE = 1;
        local *OCP::Password::prompt_password = sub { push @prompts, $_[0]; $PIN2 };
        local *OCP::SSH::run = sub {
            push @ssh, $_[1];
            return { stdout => "$TOKEN\n", stderr => '', exit => 0 };
        };
        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rv = eval { $code->() };
        $died = $@;
    }
    return { rv => $rv, died => $died, out => $out, err => $err,
             prompts => \@prompts, ssh => \@ssh };
}

# --- the state ----------------------------------------------------------------

subtest 'state: a 404 is missing, any other failed read dies with its cause' => sub {
    my $dir    = make_project();
    my $config = config_for($dir);

    my $state = sub {
        my ($api) = @_;
        my $apply = new_apply($api);
        return run_captured(sub {
            $apply->_robocop_credentials_state($api, $config,
                OCP::Secrets->new(project_dir => $dir), 'secret', host => $CP_IP);
        });
    };

    my $r = $state->(FakeApi->new);
    is $r->{died}, '', '404: no death' or diag $r->{died};
    is $r->{rv}, 'missing', '404: missing';

    $r = $state->(FakeApi->new(objects => { $SECRET => current_secret($config) }));
    is $r->{rv}, 'current', 'control: a Secret it can read is still compared'
        or diag $r->{died};

    for my $refusal (@REFUSALS) {
        my ($what, $error, $cause) = @$refusal;
        $r = $state->(FakeApi->new(objects => { $SECRET => current_secret($config) },
                                   refuse  => { $SECRET => $error }));
        ok !defined $r->{rv}, "$what: no state -- not missing, not outdated, not current";
        like $r->{died}, qr{\Acould not read Secret ocp-system/robocop-credentials: $cause.*\n\z}s,
            "$what: dies naming the Secret and the cause";
        is_deeply $r->{prompts}, [], "$what: no prompt";
    }
};

# --- ocp apply ------------------------------------------------------------------

subtest 'apply: a Secret that cannot be read is not written over -- no PIN2, no SSH' => sub {
    my $dir    = make_project();
    my $config = config_for($dir);

    my $step = sub {
        my ($api) = @_;
        my $apply = new_apply($api);
        return run_captured(sub {
            OCP::Cmd::Apply::Deploy::robocop_step($apply, $api, $config, {
                secrets => OCP::Secrets->new(project_dir => $dir),
                cp_ip   => $CP_IP,
            });
        });
    };

    my $api = FakeApi->new;
    my $r   = $step->($api);
    is $r->{rv}{state}, 'ready', 'control, 404: robocop rolled out' or diag $r->{err};
    is_deeply [ grep { $_ eq $SECRET } @{ $api->ensured } ], [ $SECRET ],
        'control, 404: the Secret is written';
    ok scalar @{ $r->{ssh} }, 'control, 404: with the token read over SSH';

    for my $refusal (@REFUSALS) {
        my ($what, $error, $cause) = @$refusal;
        $api = FakeApi->new(refuse => { $SECRET => $error });
        $r   = $step->($api);
        is $r->{rv}{state}, 'failed', "$what: the robocop step fails";
        like $r->{err},
            qr{\A  \[!!\] robocop deploy failed: could not read Secret ocp-system/robocop-credentials: $cause.*\n\z}s,
            "$what: the cause, on STDERR";
        unlike $r->{out}, qr/could not read|\[ok\]/, "$what: nothing of it on STDOUT";
        is_deeply $api->ensured, [], "$what: nothing written -- no Secret, no Deployment";
        is_deeply $r->{prompts}, [], "$what: no PIN2 asked";
        is_deeply $r->{ssh}, [], "$what: no SSH read of the join token";
    }
};

subtest 'apply, operator identity: a Secret that cannot be read is not said to be missing' => sub {
    my $dir    = make_project();
    my $config = config_for($dir);

    # An age identity that cannot open the robo private key (k216); the real
    # one is set up in t/216, what matters here is the answer it gives.
    no warnings 'redefine';
    local *OCP::Cmd::Apply::_robo_key_unreadable = sub { 1 };

    my $api = FakeApi->new(refuse => { $SECRET => api_error(403, 'Forbidden') });
    my $r = run_captured(sub {
        OCP::Cmd::Apply::Deploy::robocop_step(new_apply($api), $api, $config, {
            secrets => OCP::Secrets->new(project_dir => $dir),
            cp_ip   => $CP_IP,
        });
    });
    is $r->{rv}{state}, 'failed', 'the robocop step fails';
    unlike $r->{err}, qr/does not exist/, 'not told the Secret does not exist';
    like $r->{err}, qr{could not read Secret ocp-system/robocop-credentials: Kubernetes API error \(get\): 403 },
        'told it could not be read, and why';
    is_deeply $api->ensured, [], 'nothing written';
};

# --- ocp apply --dry-run --------------------------------------------------------

subtest 'dry run: a Secret that cannot be read is "could not be checked", not "missing"' => sub {
    my $dir    = make_project();
    my $config = config_for($dir);

    my $dry = sub {
        my ($api) = @_;
        my $apply = new_apply($api);
        return run_captured(sub {
            [ OCP::Cmd::Apply::Drift::robocop_dry_run($apply, $config, $CP_IP) ];
        });
    };

    my $r = $dry->(FakeApi->new);
    is $r->{died}, '', 'control, 404: no death' or diag $r->{died};
    is_deeply $r->{rv}, [ 'robocop-credentials', 'robocop' ],
        'control, 404: Secret and Deployment are actions';
    like $r->{out}, qr{Secret/robocop-credentials is missing\s+would write it \(secret\)},
        'control, 404: the Secret would be written';
    is $r->{err}, '', 'control, 404: nothing on STDERR';

    for my $refusal (@REFUSALS) {
        my ($what, $error, $cause) = @$refusal;
        $r = $dry->(FakeApi->new(refuse => { $SECRET => $error }));
        is $r->{died}, '', "$what: the dry run goes on" or diag $r->{died};

        my ($unknown, @rest) = @{ $r->{rv} // [] };
        is ref $unknown, 'HASH', "$what: the Secret is an entry of its own, not an action";
        $unknown = {} unless ref $unknown eq 'HASH';
        is $unknown->{kind}, 'error', "$what: of kind error -- counted as could not be checked";
        is $unknown->{label}, 'Secret/robocop-credentials', "$what: labelled with the Secret";
        like $unknown->{cause}, qr{\Acould not read Secret ocp-system/robocop-credentials: $cause}s,
            "$what: with its cause";
        is_deeply \@rest, [ 'robocop' ], "$what: the missing Deployment is still an action";

        like $r->{out}, qr{^  \[robocop\] Secret/robocop-credentials could not be checked$}m,
            "$what: could not be checked, on STDOUT";
        unlike $r->{out}, qr{Secret/robocop-credentials is |would (re)?write}, "$what: no write announced";
        like $r->{err},
            qr{\A  \[!!\] Secret/robocop-credentials not checked: could not read Secret ocp-system/robocop-credentials: $cause.*\n\z}s,
            "$what: the cause, on STDERR";
    }
};

done_testing;
