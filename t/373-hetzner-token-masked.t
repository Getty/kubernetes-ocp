#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use JSON::MaybeXS qw(encode_json);
use MIME::Base64 qw(encode_base64);
use Path::Tiny qw(path);

use lib 'lib';

use WWW::Hetzner::Cloud;
use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;

use OCP;
use OCP::Cmd::Apply;
use OCP::Cmd::Apply::Bootstrap;
use OCP::Cmd::Destroy;
use OCP::Cmd::Hetzner::List;
use OCP::Config;
use OCP::Provider;
use OCP::Provider::Hetzner;
use OCP::Secrets;
use OCP::SSH;

#
# k373: an error out of WWW::Hetzner -- the API's answer, or LWP's reason for
# not getting one -- can carry the request it was about, the Authorization
# header with the API token in it. `ocp init` (k265) and `ocp keys secure`
# (k362) masked it; every other Hetzner caller printed it or died with it as
# it came: the `ocp apply` bootstrap, `ocp destroy`, `ocp hetzner list`, and
# through the Hetzner adapter OCP::Node and robocop, which write it into an
# OCPNode's status. Now the adapter masks every error a request of its own
# raises, with the token that request went out with, and `ocp hetzner list`
# masks its one listing.
#
# Only the wire is fake: the client is the real WWW::Hetzner::Cloud each
# command builds for itself, with the token from where the command reads it,
# and every error is the one WWW::Hetzner raises. A request the test does not
# answer is refused with 401 and a body that echoes the headers it was sent --
# Authorization: Bearer <token> -- the way an answer or a transport reason can.
#

no warnings 'once';

my $TOKEN    = 'hzTOKEN-k373-local-0123456789';
my $CR_TOKEN = 'hzTOKEN-k373-cr-9876543210';

our %ROUTES;            # "METHOD /path" => answer (no query string)
our @SENT;              # "METHOD /path" of every request on the wire
our $WIRE_DIES;         # the transport dies instead of answering

sub wire {
    my ($io, $req) = @_;
    (my $path = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    ($path) = split /\?/, $path;
    my $key = $req->method . " $path";
    push @SENT, $key;

    return WWW::Hetzner::HTTPResponse->new(status => 200, content => encode_json($ROUTES{$key}))
        if $ROUTES{$key};

    my $headers = $req->headers;
    my $echo = join ' ', map { "$_: $headers->{$_}" } sort keys %$headers;
    die "Can't connect to api.hetzner.cloud:443 ($echo) at /usr/share/perl5/LWP/Protocol/http.pm line 50.\n"
        if $WIRE_DIES;
    return WWW::Hetzner::HTTPResponse->new(status => 401, content => "Unauthorized\n$echo\n");
}

# What the operator sees of an error: no token, the mask where it was, one line
# without a Perl source location.
sub masked_line {
    my ($err, $token, $what) = @_;
    ok defined $err && length $err, "$what: it fails" or return;
    unlike $err, qr/\Q$token\E/, "$what: without the token";
    like   $err, qr/Bearer \*{8}/, "$what: masked where it was";
    unlike $err, qr/ at \S+ line \d+/, "$what: no Perl source location";
    like   $err, qr/\A[^\n]+\n\z/, "$what: one line";
}

sub died {
    my ($code) = @_;
    return eval { $code->(); 1 } ? undef : $@;
}

# ---------------------------------------------------------------- the adapter

subtest 'the Hetzner adapter: every request it makes fails masked' => sub {
    for my $dies (0, 1) {
        local $WIRE_DIES = $dies;
        my $how = $dies ? 'the transport dies' : 'the API refuses';
        no warnings 'redefine';
        local *WWW::Hetzner::LWPIO::call = \&wire;
        local @SENT;
        local %ROUTES;

        my $prov = OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab');
        my $want = $dies ? qr/\ACan't connect to api\.hetzner\.cloud:443 / : qr/\AHetzner API error: 401 Unauthorized /;

        my %calls = (
            upload_ssh_key          => sub { $prov->upload_ssh_key('k', 'ssh-ed25519 AAAA k') },
            server_exists           => sub { $prov->server_exists('police1') },
            wait_for_running        => sub { $prov->wait_for_running({ id => 7 }, 1) },
            get_server_ip           => sub { $prov->get_server_ip(7) },
            delete_server           => sub { $prov->delete_server(7) },
            list_servers_by_cluster => sub { $prov->list_servers_by_cluster('lab') },
        );
        for my $name (sort keys %calls) {
            my $err = died($calls{$name});
            masked_line($err, $TOKEN, "$how, $name");
            like $err, $want, "$how, $name: what was said";
        }

        # create_server asks for the label pair first; that answer is fine here,
        # so the create itself is what fails.
        {
            local $ROUTES{'GET /servers'} = { servers => [] };
            masked_line(died(sub {
                $prov->create_server(name => 'police1', server_type => 'cpx22', ssh_keys => ['k']) }),
                $TOKEN, "$how, create_server");
            is $SENT[-1], 'POST /servers', 'create_server: the create was the request refused';
        }

        my @warned;
        {
            local $SIG{__WARN__} = sub { push @warned, @_ };
            $prov->cleanup_on_failure(7);
        }
        is scalar @warned, 1, "$how, cleanup_on_failure: one warning";
        unlike join('', @warned), qr/\Q$TOKEN\E/, "$how, cleanup_on_failure: without the token";
        like   join('', @warned), qr/\ACleanup failed for server 7: [^\n]*Bearer \*{8}[^\n]*\n+\z/,
            "$how, cleanup_on_failure: the masked line";
        unlike join('', @warned), qr/ at \S+ line \d+/, "$how, cleanup_on_failure: no Perl source location";
        like   join('', @warned), qr/\A[^\n]+\n\z/, "$how, cleanup_on_failure: one line, no blank line after it (k363)";

        ok scalar @SENT >= 7, "$how: the requests went out on the (fake) wire";
    }
};

# k363: cleanup_on_failure says the delete's error by OCP::ErrorLine::one_line.
# It added a newline to one that ended in one already -- a blank line after
# every warning (k373) -- and a delete that died with a Perl source location
# kept it, the inner one of a wrapped die in the middle too.
my $WRAPPED = "Server 7 not deleted: known_hosts not rewritten: Permission denied at lib/OCP/KnownHosts.pm line 3.\n"
            . "the server may be gone already at lib/OCP/Provider/Hetzner.pm line 9.\n";
my $WRAPPED_LINE = 'Server 7 not deleted: known_hosts not rewritten: Permission denied'
                 . ' the server may be gone already';

subtest 'the Hetzner adapter: cleanup_on_failure says a wrapped error in one line, without its locations' => sub {
    no warnings 'redefine';
    local *OCP::Provider::Hetzner::delete_server = sub { die $WRAPPED };
    my $prov = OCP::Provider::Hetzner->new(token => $TOKEN, cluster_name => 'lab');
    my @warned;
    {
        local $SIG{__WARN__} = sub { push @warned, @_ };
        $prov->cleanup_on_failure(7);
    }
    is_deeply \@warned, [ "Cleanup failed for server 7: $WRAPPED_LINE\n" ],
        'one warning, one line: no location, no blank line after it';
};

# ---------------------------------------------------------------- the factory

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}
{
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        return FakeList->new(@{ $self->{$kind} // [] });
    }
    sub get {
        my ($self, $kind, %a) = @_;
        return $self->{Secret}{ $a{name} }
            // die "404 secrets \"$a{name}\" not found\n";
    }
    sub patch { 1 }
}

sub provider_cr {
    return {
        metadata => { name => 'hetzner-default', namespace => 'ocp-system' },
        spec     => {
            type        => 'hetzner',
            clusterName => 'lab',
            hetzner     => { tokenSecretRef => { name => 'hetzner-api-token-hetzner', key => 'token' } },
        },
    };
}

sub cr_k8s {
    my (%a) = @_;
    return FakeK8s->new(
        OCPNodeProvider => [ provider_cr() ],
        Secret          => { 'hetzner-api-token-hetzner' => { data => { token => encode_base64($CR_TOKEN, '') } } },
        %a,
    );
}

subtest 'the factory: each adapter it builds masks its own token' => sub {
    no warnings 'redefine';
    local *WWW::Hetzner::LWPIO::call = \&wire;

    my $local = OCP::Provider->for_spec({ provider => 'hetzner' }, token => $TOKEN, cluster_name => 'lab');
    masked_line(died(sub { $local->list_servers_by_cluster }), $TOKEN, 'for_spec, the local token');

    my $cr = OCP::Provider->from_cr(provider_cr(), k8s => cr_k8s());
    my $err = died(sub { $cr->delete_server(9) });
    masked_line($err, $CR_TOKEN, "from_cr, the token from the provider CR's Secret");
};

# ---------------------------------------------------------------- ocp apply

package FakeOcp {
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

package main;

sub project {
    my (%a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(<<'YAML');
name: lab
control_planes:
  provider: hetzner
  server_type: cx42
  location: nbg1
  nodes: 1
YAML
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nK\n");
    $dir->child('.ocp', 'id_ed25519.pub')->spew_utf8("ssh-ed25519 AAAAboot boot\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($a{status}) if defined $a{status};
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

# STDOUT and STDERR of `ocp apply`'s bootstrap with the token in the
# environment: what it prints, then what OCP::run_cli prints of what it dies
# of -- once as "Error: ...", once raw as --verbose does.
sub bootstrap {
    my (%routes) = @_;
    my $config = project();
    my ($out, $err) = ('', '');
    local %ROUTES = %routes;
    local @SENT;
    {
        local $ENV{HETZNER_API_TOKEN} = $TOKEN;
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        local *STDERR;
        open STDERR, '>', \$err or die;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        no warnings 'redefine';
        local *WWW::Hetzner::LWPIO::call   = \&wire;
        local *OCP::Secrets::ensure_age_key = sub { 1 };
        local *OCP::SSH::new          = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::SSH::wait_for_ssh = sub { die "stop at the SSH wait\n" };
        my $ok = eval {
            OCP::Cmd::Apply::Bootstrap::bootstrap_control_plane(
                OCP::Cmd::Apply->new(command_chain => [ FakeOcp->new ]),
                $config, OCP::Secrets->new(project_dir => $config->project_dir),
                admin_key => { name => 'admin-ssh', public => 'ssh-ed25519 AAAAadmin admin' },
            );
            1;
        };
        my $died = $@;
        unless ($ok) {
            OCP::_report_error($died, 0);
            OCP::_report_error($died, 1);
        }
    }
    return { out => $out, err => $err, sent => [@SENT] };
}

subtest 'ocp apply: the bootstrap says a refused Hetzner request without the token' => sub {
    my $r = bootstrap();
    is $r->{sent}[0], 'GET /ssh_keys', 'the key upload was the request refused';
    like $r->{err}, qr/^Error: Hetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/m,
        'the error, masked';
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/, 'the token nowhere on STDOUT or STDERR, --verbose included';

    $r = bootstrap(
        'GET /ssh_keys'  => { ssh_keys => [] },
        'POST /ssh_keys' => { ssh_key => { id => 1, name => 'ocp-lab-admin',
                                           public_key => 'ssh-ed25519 AAAAadmin admin',
                                           fingerprint => 'f' } },
        'GET /servers'   => { servers => [] },
    );
    is $r->{sent}[-1], 'POST /servers', 'then the server create was the request refused';
    like $r->{err}, qr/^Error: Hetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/m,
        'the error, masked';
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/, 'the token nowhere on STDOUT or STDERR, --verbose included';
};

# ---------------------------------------------------------------- ocp destroy

# `ocp destroy --force` through OCP::run_cli. The cluster API, when given, is
# what _cluster_api hands back instead of reading the kubeconfig.
sub destroy {
    my ($config, %a) = @_;
    my ($out, $err, $code) = ('', '');
    local %ROUTES;
    local @SENT;
    {
        local @ARGV = ('-c', $config->file, 'destroy', '--force');
        local $ENV{HETZNER_API_TOKEN} = $TOKEN;
        local *STDOUT;
        open STDOUT, '>', \$out or die;
        local *STDERR;
        open STDERR, '>', \$err or die;
        local $SIG{__WARN__} = sub { print STDERR @_ };
        no warnings 'redefine';
        local *WWW::Hetzner::LWPIO::call = \&wire;
        local *OCP::Cmd::Destroy::_cluster_api = sub { $a{k8s} ? $_[0]->k8s($a{k8s}) : undef };
        $code = OCP->run_cli;
    }
    return { out => $out, err => $err, code => $code, sent => [@SENT] };
}

my $STATUS = <<'YAML';
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
YAML

subtest 'ocp destroy: a refused delete is said without the token' => sub {
    my $r = destroy(project(status => $STATUS));
    ok scalar(grep { $_ eq 'DELETE /servers/111' } @{ $r->{sent} }), 'the delete went out';
    like $r->{err}, qr/^  Warning: Hetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/m,
        'the warning, masked';
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/, 'the token nowhere on STDOUT or STDERR';
    is $r->{code}, 1, 'exit 1: the server is still there';
};

# k363: the warning for a failed delete is said by OCP::ErrorLine::one_line.
# "  Warning: $@\n" added a newline to an error that ended in one already
# (k373), and kept a Perl source location, the inner one of a wrapped die in
# the middle too.
subtest 'ocp destroy: a delete that died of a wrapped error is one Warning line, without its locations' => sub {
    no warnings 'redefine';
    local *OCP::Provider::Hetzner::delete_server = sub { die $WRAPPED =~ s/Server 7/Server 111/r };
    my $r = destroy(project(status => $STATUS));
    (my $line = $WRAPPED_LINE) =~ s/Server 7/Server 111/;
    # The next block is the old-label search, failed under the same 401 and
    # said since k396; before, it was the INCOMPLETE block.
    like $r->{err}, qr/^  Warning: \Q$line\E\n\n\[!!\] The search under the old label ocp-cluster=hetzner-default failed: /m,
        'the warning: one line, then only the blank line the next [!!] block opens with';
    unlike $r->{err}, qr/ at lib\/OCP\/(?:KnownHosts|Provider\/Hetzner)\.pm line \d+/,
        'neither location on STDERR';
    is $r->{code}, 1, 'exit 1: the server is still there';
};

subtest 'ocp destroy: a refused label search is said without the token' => sub {
    my $r = destroy(project(status => "nodes: []\n"));
    ok scalar(grep { $_ eq 'GET /servers' } @{ $r->{sent} }), 'the label search went out';
    like $r->{err}, qr/the label search failed: Hetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/,
        'the search failure, masked';
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/, 'the token nowhere on STDOUT or STDERR';
};

subtest "ocp destroy: a worker deleted with its provider CR's token, masked too" => sub {
    my $k8s = cr_k8s(OCPNode => [ {
        metadata => { name => 'w1', namespace => 'ocp-system' },
        spec     => { role => 'worker', providerRef => 'hetzner-default' },
        status   => { phase => 'Ready', providerId => '222', publicIP => '2.2.2.2' },
    } ]);
    my $r = destroy(project(status => $STATUS), k8s => $k8s);
    ok scalar(grep { $_ eq 'DELETE /servers/222' } @{ $r->{sent} }), 'the worker delete went out';
    my @warnings = $r->{err} =~ /^  Warning: ([^\n]*)$/mg;
    is scalar @warnings, 2, 'both deletes refused, both said';
    like $_, qr/\AHetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/, 'masked' for @warnings;
    unlike "$r->{out}$r->{err}", qr/\Q$CR_TOKEN\E/, "the provider CR's token nowhere on STDOUT or STDERR";
    unlike "$r->{out}$r->{err}", qr/\Q$TOKEN\E/,    'the local token neither';
};

# ---------------------------------------------------------------- ocp hetzner list

subtest 'ocp hetzner list: a refused listing is said without the token' => sub {
    my $config = project();
    for my $verbose (0, 1) {
        my ($out, $err, $code) = ('', '');
        local @SENT;
        {
            local @ARGV = ('-c', $config->file, ($verbose ? '--verbose' : ()), 'hetzner', 'list');
            local $ENV{HETZNER_API_TOKEN} = $TOKEN;
            local *STDOUT;
            open STDOUT, '>', \$out or die;
            local *STDERR;
            open STDERR, '>', \$err or die;
            no warnings 'redefine';
            local *WWW::Hetzner::LWPIO::call = \&wire;
            $code = OCP->run_cli;
        }
        my $how = $verbose ? 'with --verbose' : 'without --verbose';
        is_deeply \@SENT, [ 'GET /servers' ], "$how: the listing went out";
        is $code, 1, "$how: exit 1";
        like $err, qr/Hetzner API error: 401 Unauthorized [^\n]*Bearer \*{8}/, "$how: the error, masked";
        unlike "$out$err", qr/\Q$TOKEN\E/, "$how: the token nowhere on STDOUT or STDERR";
    }
};

done_testing;
