#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Path::Tiny qw( tempdir );

use lib 'lib';

use Kubernetes::REST::APIError;
use OCP::Cmd::Destroy;
use OCP::Cmd::Keys::Operator::Add;
use OCP::Cmd::Keys::Secure;
use OCP::Cmd::Node::Add;
use OCP::Config;

#
# k433: OCP::Role::Cmd::provider_crs took a failed OCPNodeProvider list for
# an empty one. ocp destroy went on as if the cluster had no provider CR,
# node add answered "No OCPNodeProvider exists", keys secure skipped the
# Hetzner upload as if no Hetzner were in use -- the cause said nowhere. Now
# the failure is one line, "Could not read the OCPNodeProviders from the
# cluster API: WHY", the way the OCPNode list says its failure since k396:
# callers that cannot go on die with it, the ones that go on say it on
# STDERR with what it costs them.
#

package FakeList { sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
package FakeIO   { sub new { bless {}, $_[0] } sub object_to_struct { $_[1] } }
package FakeK8s {
    # providers: an arrayref of CR hashes, or what the list dies with.
    sub new { my ($c, %a) = @_; bless { %a, calls => [] }, $c }
    sub k8s { FakeIO->new }
    sub list {
        my ($s, $kind) = @_;
        push @{ $s->{calls} }, [ 'list', $kind ];
        if ($kind eq 'OCPNodeProvider') {
            die $s->{providers} unless ref $s->{providers} eq 'ARRAY';
            return FakeList->new($s->{providers});
        }
        return FakeList->new($s->{nodes} // []);
    }
    sub get {
        my ($s, $kind, %a) = @_;
        push @{ $s->{calls} }, [ 'get', $kind, $a{name} ];
        die $s->{providers} if $kind eq 'OCPNodeProvider' && ref $s->{providers} ne 'ARRAY';
        die "404: not found $kind/$a{name}\n";
    }
    sub ensure { my ($s, $o) = @_; push @{ $s->{calls} }, [ 'ensure', $o ]; $o }
    sub patch  { my ($s, $kind) = @_; push @{ $s->{calls} }, [ 'patch', $kind ]; {} }
}
package FakeOcp { sub new { my ($c, %a) = @_; bless {%a}, $c } sub config { $_[0]{config} } }
package main;

my $LINE = 'Could not read the OCPNodeProviders from the cluster API: ';

# The two shapes a list dies with: Kubernetes::REST's error for an HTTP
# status, and a plain croak with its source location.
my %FAILURE = (
    'an APIError' => Kubernetes::REST::APIError->new(code => 403, context => 'list',
        body => '{"kind":"Status","status":"Failure","reason":"Forbidden","code":403}'),
    'a croak'     => "connection reset by peer at /opt/lib/Some/IO.pm line 42.\n",
);

sub captured {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $o, '>', \$out or die;
    open my $e, '>', \$err or die;
    my @r = do { local *STDOUT = $o; local *STDERR = $e; $code->() };
    return ($out, $err, @r);
}

for my $shape (sort keys %FAILURE) {
    my $failure = $FAILURE{$shape};

    subtest "provider_crs, the list fails with $shape: dies with one line" => sub {
        my $cmd = OCP::Cmd::Node::Add->new;
        my $k8s = FakeK8s->new(providers => $failure);
        my @got = eval { $cmd->provider_crs($k8s) };
        my $err = $@;
        like $err, qr/\AERROR: \Q$LINE\E\S/, 'says the list failed, not that there is none';
        unlike $err, qr/ at \S+ line \d+/, 'no Perl source location';
        is scalar(split /\n/, $err), 1, 'one line';
        like $err, qr/403|connection reset by peer/, 'with the cause';
    };

    subtest "provider_crs with unread, the list fails with $shape: the line, no die" => sub {
        my $cmd = OCP::Cmd::Node::Add->new;
        my @got = $cmd->provider_crs(FakeK8s->new(providers => $failure), unread => \my $why);
        is_deeply \@got, [], 'no providers';
        like $why, qr/\A\Q$LINE\E\S[^\n]*\z/, 'the one line, without ERROR:';
    };
}

subtest 'provider_crs, the list answers empty: no line, as before' => sub {
    my $cmd = OCP::Cmd::Node::Add->new;
    my @got = $cmd->provider_crs(FakeK8s->new(providers => []), unread => \my $why);
    is_deeply \@got, [], 'no providers';
    is $why, undef, 'nothing unread';
    is_deeply [ eval { $cmd->provider_crs(FakeK8s->new(providers => [])) } ], [], 'no die without unread';
    is $@, '', 'no error';
};

subtest 'node add without --provider: the failure, not "No OCPNodeProvider exists"' => sub {
    my $k8s = FakeK8s->new(providers => $FAILURE{'an APIError'});
    my $add = OCP::Cmd::Node::Add->new(k8s => $k8s, host => '10.0.0.9', name => 'worker-9');
    my ($out, $err, $rc) = captured(sub {
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_preflight_host = sub { push @{ $k8s->{calls} }, [ 'preflight' ] };
        local *OCP::Cmd::Node::Add::_cli_reconcile  = sub { push @{ $k8s->{calls} }, [ 'reconcile' ]; 1 };
        my $r = eval { $add->execute([], []) };
        defined $r ? $r : "died: $@";
    });
    like $rc, qr/\Adied: ERROR: \Q$LINE\E/, 'dies with the list failure';
    unlike $rc, qr/No OCPNodeProvider exists/, 'not taken for an empty cluster';
    is_deeply [ grep { $_->[0] =~ /^(?:ensure|patch|preflight|reconcile)$/ } @{ $k8s->{calls} } ], [],
        'nothing written, no probe';
};

subtest 'provider_cr, the get and the list fail: the failure, not "Unknown provider"' => sub {
    my $cmd = OCP::Cmd::Node::Add->new;
    eval { $cmd->provider_cr(FakeK8s->new(providers => $FAILURE{'a croak'}), 'ssh-default') };
    like $@, qr/\AERROR: \Q$LINE\Econnection reset by peer\n\z/, 'the list failure, in one line';
};

subtest 'destroy: the OCPNodes answer, the providers do not -- said, and the run goes on' => sub {
    my $node = sub {
        my ($name, $ref) = @_;
        return { metadata => { name => $name },
                 spec     => { role => 'worker', providerRef => $ref },
                 status   => { providerId => '42', publicIP => '10.0.0.7' } };
    };
    my $k8s = FakeK8s->new(providers => $FAILURE{'an APIError'},
                           nodes     => [ $node->('w1', 'hetzner-default'), $node->('w2', 'hz-b') ]);
    my $cmd = OCP::Cmd::Destroy->new;
    my ($out, $err, @entries) = captured(sub { $cmd->_ocpnode_entries($k8s) });

    like $err, qr/^\[!!\] \Q$LINE\E\S[^\n]*$/m, 'the failure, in one line on STDERR';
    like $err, qr/no provider CR's Hetzner token is used/, 'says what it costs the teardown';
    is $out, '', 'nothing on STDOUT';
    is_deeply [ map { $_->[0]{name} } @entries ], [ 'w1' ],
        'the <type>-default node goes on; the other is not guessed';
    like $err, qr/OCPNode w2: provider 'hz-b' is unknown here; it is NOT torn down/,
        'the node whose type only its CR knows is named';
    is $cmd->_no_token_reason({ provider_ref => 'hetzner-default' }),
        'no local Hetzner token, and the OCPNodeProviders could not be read',
        'the refusal reason says the CRs were unread, not that there is none';
};

subtest 'destroy, control: an empty provider list says nothing' => sub {
    my $k8s = FakeK8s->new(providers => [], nodes => []);
    my $cmd = OCP::Cmd::Destroy->new;
    my ($out, $err) = captured(sub { $cmd->_ocpnode_entries($k8s) });
    is $err, '', 'nothing on STDERR';
    is $cmd->_no_token_reason({ provider_ref => 'hetzner-default' }),
        'no local Hetzner token, and no OCPNodeProvider/hetzner-default in the cluster',
        'the reason as before';
};

# keys secure and keys operator add decide whether Hetzner is in use from the
# provider CRs when ocp.yaml names none.
my $dir = tempdir;
$dir->child('ocp.yaml')->spew(<<'YAML');
name: prod
control_planes:
  - provider: ssh
    host: 10.0.0.1
YAML
my $config = OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
my $ocp    = FakeOcp->new(config => $config->file);

subtest 'keys secure: the providers unread -- said, the upload not counted as done' => sub {
    my $cmd = OCP::Cmd::Keys::Secure->new(command_chain => [ $ocp ]);
    my $k8s = FakeK8s->new(providers => $FAILURE{'an APIError'});
    my ($out, $err, $ok) = captured(sub { $cmd->_upload_to_hetzner($config, undef, $k8s) });
    is $ok, 0, 'not true: the run ends with exit 1';
    like $err, qr/^\[!!\] \Q$LINE\E\S[^\n]*$/m, 'the failure, in one line on STDERR';
    like $err, qr/Whether this project uses Hetzner is unknown/, 'says what is unknown';
    like $err, qr/\Q${\ $config->admin_ssh_key_name }\E and \Q${\ $config->robo_ssh_key_name }\E/,
        'names the keys to add by hand';
};

subtest 'keys secure, control: no hetzner provider CR -- nothing to upload, nothing said' => sub {
    my $cmd = OCP::Cmd::Keys::Secure->new(command_chain => [ $ocp ]);
    my ($out, $err, $ok) = captured(sub {
        $cmd->_upload_to_hetzner($config, undef, FakeK8s->new(providers => []))
    });
    is $ok, 1, 'true';
    is $err, '', 'nothing on STDERR';
};

subtest 'keys operator add: the providers unread -- said, and the Hetzner note given' => sub {
    my $cmd = OCP::Cmd::Keys::Operator::Add->new(command_chain => [ $ocp ]);
    my ($out, $err) = captured(sub {
        $cmd->_print_hetzner_gap($config, FakeK8s->new(providers => $FAILURE{'a croak'}))
    });
    like $err, qr/^\[!!\] \Q$LINE\Econnection reset by peer$/m, 'the failure, in one line on STDERR';
    like $out, qr/Hetzner: servers created from now on/, 'the note, as it holds if Hetzner is in use';
};

subtest 'keys operator add, control: no hetzner provider CR -- no note' => sub {
    my $cmd = OCP::Cmd::Keys::Operator::Add->new(command_chain => [ $ocp ]);
    my ($out, $err) = captured(sub {
        $cmd->_print_hetzner_gap($config, FakeK8s->new(providers => []))
    });
    is $out, '', 'no note';
    is $err, '', 'nothing on STDERR';
};

done_testing;
