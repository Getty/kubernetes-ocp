#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use lib 'lib';

use OCP;
use OCP::Cmd::Node::Add;
use OCP::Cmd::Provider::Rm;

#
# A provider is addressed by the NAME of its OCPNodeProvider CR, but
# `ocp init --provider` and spec.type speak provider TYPES. Writing the type
#
#     ocp node add otho-gpu --role worker --provider ssh --host ...
#
# is the mistake that actually happens: the CR `ocp apply` writes is called
# `ssh-default`. The old answer was "Provider 'ssh' not found" — a correct
# rejection that helped with nothing, and it cost a SPIKE iteration (karr #89).
#
# What is tested here: a refused provider name says what would have worked —
# every existing provider with BOTH its name and its type, because the type is
# what got typed instead. The listing lives in OCP::Role::Cmd, so every command
# taking a provider name answers with the same text; that sameness is asserted
# rather than assumed.
#
# What is NOT wanted, and asserted to stay that way: 'ssh' resolving to
# 'ssh-default'. That would open a second namespace next to the CR names, and
# nothing stops anyone from naming a provider 'ssh'. Input we do not understand
# is refused and explained (karr #67, #37, #73).
#

{
    package FakeList;
    sub new   { my ($c, $items) = @_; bless { items => $items }, $c }
    sub items { $_[0]->{items} }
}

{
    package FakeIO;
    sub new              { bless {}, $_[0] }
    sub object_to_struct { $_[1] }
}

{
    package FakeK8s;

    my $_io = FakeIO->new;

    sub new {
        my ($class, %args) = @_;
        return bless {
            providers => $args{providers} // [],
            nodes     => $args{nodes}     // [],
            calls     => [],
        }, $class;
    }

    sub k8s { $_io }

    sub list {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['list', $kind, \%args];
        return FakeList->new($self->{providers}) if $kind eq 'OCPNodeProvider';
        return FakeList->new($self->{nodes})     if $kind eq 'OCPNode';
        return FakeList->new([]);
    }

    sub get {
        my ($self, $kind, %args) = @_;
        push @{$self->{calls}}, ['get', $kind, \%args];
        my $name = $args{name} // '';
        if ($kind eq 'OCPNodeProvider') {
            for my $p (@{ $self->{providers} }) {
                return $p if $p->{metadata}{name} eq $name;
            }
            die "404: not found OCPNodeProvider/$name\n";
        }
        return undef;
    }

    sub ensure { push @{$_[0]->{calls}}, ['ensure', $_[1]]; $_[1] }
    sub delete { my ($s, $k, %a) = @_; push @{$s->{calls}}, ['delete', $k, \%a]; 1 }

    sub calls_of {
        my ($self, $verb) = @_;
        return grep { $_->[0] eq $verb } @{$self->{calls}};
    }
}

my @BOOTSTRAPPED = (
    {
        metadata => { name => 'ssh-default', namespace => 'ocp-system', annotations => {} },
        spec     => { type => 'ssh' },
    },
    {
        metadata => { name => 'hetzner-default', namespace => 'ocp-system', annotations => {} },
        spec     => { type => 'hetzner' },
    },
);

sub node_add_error {
    my (%args) = @_;
    my $k8s = FakeK8s->new(providers => $args{providers});
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'otho-gpu',
        role     => 'worker',
        host     => '10.0.0.5',
        provider => $args{provider},
    );
    eval { $add->execute([], []) };
    return ($@, $k8s);
}

sub provider_rm_error {
    my (%args) = @_;
    my $k8s = FakeK8s->new(providers => $args{providers});
    my $rm  = OCP::Cmd::Provider::Rm->new(k8s => $k8s, name => $args{provider});
    eval { $rm->execute([], []) };
    return ($@, $k8s);
}

# -------------------------------------------------------------------------

subtest 'ocp node add --provider ssh names the providers that exist' => sub {
    my ($err, $k8s) = node_add_error(
        providers => [@BOOTSTRAPPED],
        provider  => 'ssh',
    );

    ok $err, 'the rejected name is refused';
    like $err, qr/^Unknown provider 'ssh'\./,
        "first line names the word that was not understood";
    like $err, qr/^Available: .*\bssh-default \(type ssh\)/m,
        'lists the CR name with its type';
    like $err, qr/^Available: .*\bhetzner-default \(type hetzner\)/m,
        'lists every provider, not just the matching type';
    like $err, qr/'ssh' is a provider type, not a provider name/,
        'says what kind of mistake this was';
    like $err, qr/'ssh-default'/,
        'names the CR that ocp apply writes for that type';

    is scalar($k8s->calls_of('ensure')), 0,
        'no OCPNode CR is written when the provider is refused';
};

subtest 'a typo is listed too, but is not called a type' => sub {
    my ($err) = node_add_error(
        providers => [@BOOTSTRAPPED],
        provider  => 'ssh-defualt',
    );

    like $err, qr/^Unknown provider 'ssh-defualt'\./, 'names the typo';
    like $err, qr/^Available: .*ssh-default \(type ssh\)/m, 'lists the real name';
    unlike $err, qr/is a provider type/,
        'no type hint for a name that is not a type';
};

subtest 'a type is never resolved to the CR that carries it' => sub {
    my $k8s = FakeK8s->new(providers => [@BOOTSTRAPPED]);
    my $add = OCP::Cmd::Node::Add->new(
        k8s      => $k8s,
        name     => 'otho-gpu',
        host     => '10.0.0.5',
        provider => 'ssh',
    );

    eval { $add->execute([], []) };
    ok $@, 'ocp node add --provider ssh still fails';

    my @ensures = $k8s->calls_of('ensure');
    is scalar(@ensures), 0, 'nothing was guessed into existence';
};

subtest 'an empty cluster points at ocp apply, not at an empty list' => sub {
    my ($err) = node_add_error(providers => [], provider => 'ssh');

    like $err, qr/^Unknown provider 'ssh'\./, 'still names the input';
    like $err, qr/No OCPNodeProvider exists in this cluster/,
        'says the cluster has none';
    like $err, qr/'ocp apply'/,     'points at ocp apply';
    like $err, qr/'ocp provider add'/, 'points at ocp provider add';
    unlike $err, qr/^Available:/m,  'no empty Available: line';
    unlike $err, qr/is a provider type/,
        'no type hint when there is no CR to be confused with';
};

subtest 'ocp provider rm gives the same answer as ocp node add' => sub {
    my ($rm_err, $k8s) = provider_rm_error(
        providers => [@BOOTSTRAPPED],
        provider  => 'ssh',
    );
    my ($add_err) = node_add_error(
        providers => [@BOOTSTRAPPED],
        provider  => 'ssh',
    );

    ok $rm_err, 'ocp provider rm ssh is refused';
    is $rm_err, $add_err,
        'both commands produce one error picture, not two';
    is scalar($k8s->calls_of('delete')), 0,
        'nothing is deleted when the name is refused';
};

subtest 'ocp provider rm on an empty cluster' => sub {
    my ($err, $k8s) = provider_rm_error(providers => [], provider => 'ssh-default');

    like $err, qr/^Unknown provider 'ssh-default'\./, 'names the input';
    like $err, qr/No OCPNodeProvider exists in this cluster/, 'says the cluster has none';
    is scalar($k8s->calls_of('delete')), 0, 'nothing is deleted';
};

subtest 'several providers and no --provider lists the candidates' => sub {
    my ($err) = node_add_error(providers => [@BOOTSTRAPPED], provider => undef);

    like $err, qr/Multiple providers found, --provider required\./,
        'still asks for --provider';
    like $err, qr/^Available: .*ssh-default \(type ssh\)/m,
        'and now says which ones it means';
    like $err, qr/hetzner-default \(type hetzner\)/,
        'with their types';
};

subtest 'the rejection goes to STDERR and exits non-zero' => sub {
    # This is the path bin/ocp takes: OCP::run_cli hands the exception to
    # _report_error, whose return value becomes the process exit code.
    my ($err) = node_add_error(providers => [@BOOTSTRAPPED], provider => 'ssh');

    my $stderr = '';
    my $rc;
    {
        open my $fh, '>', \$stderr or die "capture stderr: $!";
        local *STDERR = $fh;
        $rc = OCP::_report_error($err, 0);
    }

    isnt $rc, 0, 'exit code stays non-zero';
    like $stderr, qr/^Error: Unknown provider 'ssh'\./,
        'STDERR carries the message under the CLI error label';
    like $stderr, qr/^Available: .*ssh-default \(type ssh\)/m,
        'STDERR carries the listing';
    unlike $stderr, qr/at \S+ line \d+/,
        'no Perl location leaks into the operator-facing message';
};

subtest 'same shape as an unknown command word (karr #67)' => sub {
    my $cmd_err = do {
        my @argv = ('quatschkommando');
        eval { OCP::_resolve_commands('OCP', \@argv) };
        $@;
    };
    my ($provider_err) = node_add_error(
        providers => [@BOOTSTRAPPED],
        provider  => 'ssh',
    );

    for my $case (["unknown command", $cmd_err], ["unknown provider", $provider_err]) {
        my ($label, $err) = @$case;
        like $err, qr/^Unknown \w+ '[^']+'/,
            "$label: opens by naming what it did not understand";
        like $err, qr/^Available: /m,
            "$label: follows with what would have worked";
        like $err, qr/\n\z/,
            "$label: ends in a newline, so no source location is appended";
    }
};

done_testing;
