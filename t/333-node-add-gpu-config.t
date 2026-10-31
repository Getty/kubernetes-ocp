#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Apply::Validate;
use OCP::Cmd::Node::Add;

#
# k333: `ocp node add --gpu` read Config::gpu_enabled only once the node had
# joined and was Ready (_ensure_gpu_stack), outside an eval. Since k320 a
# malformed gpu.enabled (`no`) croaks there -- after the join, with the node
# in the cluster. A malformed gpu.driver, gpu.toolkit or gpu.amd key was read
# after the join as well, by the GPU steps node add hands on to, and failed
# them there.
#
# Decision: with --gpu and without --nowait, validate()'s lines for the gpu:
# block -- all of them, nothing else -- refuse the command before the cluster
# is asked anything: before the kubeconfig (PIN1), the provider lookup, the
# OCPNode write, the host's SSH probe (PIN2) and the join. Every line at once,
# STDOUT empty, exit 1 with the lines on STDERR (bin/ocp prints the die).
#
# Not refused: a line validate() has outside gpu: (node add does not read it;
# `ocp apply` refuses it), --gpu --nowait (reads no gpu: key, leaves the stack
# to `ocp apply`), and a run without --gpu.
#

local @ARGV = ();
my $ocp = OCP->new;
my $bin = "$FindBin::Bin/../bin/ocp";
my $lib = "$FindBin::Bin/../lib";

my $CP = { provider => 'ssh', host => 'cp.k333.test' };

sub project {
    my ($spec) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(
        YAML::XS::Dump({ name => 'k333', control_planes => $CP, %$spec }));
    return $dir;
}

sub config_of {
    my ($dir) = @_;
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify, ocp => $ocp);
}

{ package FakeList; sub new { bless { items => $_[1] }, $_[0] } sub items { $_[0]{items} } }
{ package FakeIO;   sub new { bless {}, $_[0] } sub object_to_struct { $_[1] } }
{
    # Every question to the cluster lands in the shared step log.
    package FakeK8s;
    my $io = FakeIO->new;
    my $provider = { metadata => { name => 'ssh-default', namespace => 'ocp-system',
                                   annotations => {} },
                     spec     => { type => 'ssh' } };
    sub new  { my ($c, $steps) = @_; bless { steps => $steps }, $c }
    sub k8s  { $io }
    sub list { my ($s, $kind) = @_; push @{ $s->{steps} }, "list $kind";
               FakeList->new($kind eq 'OCPNodeProvider' ? [ $provider ] : []) }
    sub get  { my ($s, $kind) = @_; push @{ $s->{steps} }, "get $kind";
               $kind eq 'OCPNodeProvider' ? $provider : undef }
    sub ensure { my ($s, $cr) = @_; push @{ $s->{steps} }, 'write OCPNode'; $cr }
}

# `ocp node add brain --host 10.0.0.5 [--gpu] [--nowait]` against the project
# in $dir. Every step that reaches past this machine is a recorder: the
# kubeconfig (_k8s, PIN1), the SSH probe (_preflight_host, PIN2), the join on
# either path, and the GPU stack (the real one with real_stack, which reads
# gpu.enabled as it did since k320). Returns rc, out, err (a "\n"-terminated
# die is what bin/ocp prints on STDERR, exit 1) and the steps taken.
sub add {
    my ($dir, %o) = @_;
    my $config = config_of($dir);
    my @steps;
    my $api = FakeK8s->new(\@steps);
    my $add = OCP::Cmd::Node::Add->new(
        name => 'brain',
        host => '10.0.0.5',
        ($o{gpu}    ? (gpu    => 1) : ()),
        ($o{nowait} ? (nowait => 1) : ()),
    );
    my $real_stack = \&OCP::Cmd::Node::Add::_ensure_gpu_stack;

    my ($out, $err, $rc) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Cmd::Node::Add::_config           = sub { $config };
        local *OCP::Cmd::Node::Add::_k8s              = sub { push @steps, 'kubeconfig (PIN1)'; $api };
        local *OCP::Cmd::Node::Add::_ssh_keys_note    = sub { '' };
        local *OCP::Cmd::Node::Add::_robocop_ready    = sub { push @steps, 'get Deployment'; $o{robocop} ? 1 : 0 };
        local *OCP::Cmd::Node::Add::_preflight_host   = sub { push @steps, 'SSH probe (PIN2)'; 1 };
        local *OCP::Cmd::Node::Add::_cli_reconcile    = sub { push @steps, 'join (CLI)'; 1 };
        local *OCP::Cmd::Node::Add::_poll_until_ready = sub { push @steps, 'join (robocop)'; 1 };
        local *OCP::Cmd::Node::Add::_ensure_gpu_stack = sub {
            push @steps, 'GPU stack';
            return $o{real_stack} ? $real_stack->(@_) : 1;
        };
        local *OCP::Cmd::Node::Add::_check_node_ip = sub { 1 };

        open my $ofh, '>', \$out or die $!;
        open my $efh, '>', \$err or die $!;
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        $rc = eval { $add->execute([], []) };
        if (my $e = $@) {
            $err .= (ref $e || $e !~ /\n\z/) ? "UNEXPECTED DIE: $e" : $e;
            $rc = 1;
        }
    }
    return { rc => $rc, out => $out, err => $err, steps => \@steps, config => $config };
}

# validate()'s lines for the gpu: block of the project in $dir.
sub gpu_lines { grep { /\Agpu[.:]/ } config_of($_[0])->validate }

# The refusal: exit 1, every gpu: line of validate() at once, nothing done.
sub refused_ok {
    my ($r, $want, $name) = @_;
    my $n = @$want;
    subtest $name => sub {
        is $r->{rc}, 1, 'exit 1';
        is_deeply $r->{steps}, [], 'nothing done: no kubeconfig (PIN1), no cluster read or write, '
            . 'no SSH probe (PIN2), no join, no GPU stack' or diag explain $r->{steps};
        is $r->{out}, '', 'nothing on STDOUT';
        unlike $r->{err}, qr/UNEXPECTED DIE| at \S+ line \d+/, 'no Perl error text';
        like $r->{err}, qr/\A\S*ocp\.yaml has $n errors? in its gpu: block:\n/, "opens with the count ($n)"
            or diag $r->{err};
        like $r->{err}, qr/^  - \Q$_\E$/m, "names: $_" for @$want;
        my @listed = $r->{err} =~ /^  - (.*)$/mg;
        is_deeply \@listed, $want, "validate()'s gpu: lines, all of them, in its order";
        like $r->{err}, qr/Nothing was done:/, 'says nothing was done';
    };
}

# --- 1. the card: gpu.enabled: no ----------------------------------------------

my $NO = "gpu.enabled: must be true or false, not 'no'; write enabled: false";

{
    my $dir = project({ gpu => { enabled => 'no' } });
    is_deeply [ gpu_lines($dir) ], [ $NO ], 'fixture: validate() has its line for gpu.enabled: no';

    refused_ok(add($dir, gpu => 1, real_stack => 1), [ $NO ],
        'k333 gpu.enabled: no, CLI path: refused before anything, not after the join');
    refused_ok(add($dir, gpu => 1, robocop => 1, real_stack => 1), [ $NO ],
        'k333 gpu.enabled: no, robocop path: refused before the OCPNode is written');
}

# --- 2. every gpu: line validate() has -- what the GPU stack reads ------------

my %SHAPES = (
    'gpu: false'                       => { gpu => JSON::PP::false() },
    'gpu.toolkit: off'                 => { gpu => { toolkit => 'off' } },
    'gpu.driver: oprator'              => { gpu => { driver => 'oprator' } },
    'gpu.amd: a string'                => { gpu => { amd => 'dra' } },
    'gpu.amd.allocation: dar'          => { gpu => { amd => { allocation => 'dar' } } },
    'gpu.amd.resource_naming: a list'  => { gpu => { amd => { resource_naming => [ 'single' ] } } },
    'gpu.amd.alocation (unknown key)'  => { gpu => { amd => { alocation => 'dra' } } },
    'gpu.enable (unknown key)'         => { gpu => { enable => JSON::PP::false() } },
    'gpu.amd.labeller: no'             => { gpu => { amd => { labeller => 'no' } } },
    'gpu.amd.metrics: yes'             => { gpu => { amd => { metrics => 'yes' } } },
    'gpu.amd.integrated: a list'       => { gpu => { amd => { integrated => [ JSON::PP::true() ] } } },
);
for my $what (sort keys %SHAPES) {
    my $dir  = project($SHAPES{$what});
    my @want = gpu_lines($dir);
    is scalar(@want), 1, "fixture: validate() has one gpu: line for $what" or diag explain \@want;
    refused_ok(add($dir, gpu => 1), \@want, "$what: refused before anything");
}

subtest 'gpu: false is refused with validate()\'s own words' => sub {
    my $r = add(project({ gpu => JSON::PP::false() }), gpu => 1, real_stack => 1);
    like $r->{err}, qr/^  - gpu: must be a mapping, not false; write gpu: \{ enabled: false \}$/m,
        'the line t/296 pins for validate()';
};

# --- 3. several at once --------------------------------------------------------

{
    my $dir = project({ gpu => { enabled => 'no', driver => 'oprator',
                                 amd => { allocation => 'dar', metrics => 'yes' } } });
    my @want = gpu_lines($dir);
    is scalar(@want), 4, 'fixture: four gpu: lines' or diag explain \@want;
    refused_ok(add($dir, gpu => 1), \@want, 'four gpu: lines: all of them at once');
}

# --- 4. what is not refused ----------------------------------------------------

# A line validate() has outside gpu: is no line node add reads. `ocp apply`
# refuses it; node add goes on.
{
    my $dir = project({ lbipam => 'off' });
    my @all = config_of($dir)->validate;
    is_deeply \@all, [ "lbipam: must be true or false, not 'off'; write lbipam: false" ],
        'fixture: validate() has a line, outside gpu:';
    my $r = add($dir, gpu => 1);
    subtest 'a line outside gpu: does not hold node add --gpu up' => sub {
        is $r->{rc}, 0, 'exit 0';
        is $r->{err}, '', 'nothing on STDERR';
        ok((grep { $_ eq 'write OCPNode' } @{ $r->{steps} }), 'the OCPNode is written');
        ok((grep { $_ eq 'GPU stack' } @{ $r->{steps} }), 'and the GPU stack is set up');
    };
}

subtest 'a gpu: line beside one outside it: only the gpu: line is node add\'s' => sub {
    my $dir = project({ lbipam => 'off', gpu => { enabled => 'no' } });
    is scalar(() = config_of($dir)->validate), 2, 'fixture: validate() has two lines';
    my $r = add($dir, gpu => 1);
    is $r->{rc}, 1, 'refused';
    like $r->{err}, qr/\A\S*ocp\.yaml has 1 error in its gpu: block:\n  - \Q$NO\E\n/, 'the gpu: line, counted alone';
    unlike $r->{err}, qr/lbipam/, 'not the lbipam: line';
    is_deeply $r->{steps}, [], 'nothing done';
};

subtest '--gpu --nowait reads no gpu: key and is not refused; ocp apply refuses the line' => sub {
    my $dir = project({ gpu => { enabled => 'no' } });
    my $r = add($dir, gpu => 1, nowait => 1);
    is $r->{rc}, 0, 'exit 0';
    is $r->{out}, "brain\n", 'STDOUT is the node name';
    ok((grep { $_ eq 'write OCPNode' } @{ $r->{steps} }), 'the OCPNode is written');
    ok(!(grep { /join|GPU stack/ } @{ $r->{steps} }), 'no join waited for, no GPU stack read');
    like $r->{err}, qr/run `ocp apply` to deploy its GPU stack/, 'the stack is left to ocp apply';

    my $died = eval { OCP::Cmd::Apply::Validate::refuse_invalid_config(config_of($dir)); 0 } // 1;
    ok $died, 'which refuses ocp.yaml before it touches anything (k255)';
    like $@, qr/^  - \Q$NO\E$/m, 'with the same line';
};

subtest 'without --gpu the gpu: block is not read and not refused' => sub {
    my $r = add(project({ gpu => { enabled => 'no' } }));
    is $r->{rc}, 0, 'exit 0';
    is $r->{err}, '', 'nothing on STDERR';
    ok((grep { $_ eq 'join (CLI)' } @{ $r->{steps} }), 'the node joins');
    ok(!(grep { $_ eq 'GPU stack' } @{ $r->{steps} }), 'no GPU stack');
};

subtest 'a valid gpu: block passes: the run goes on to the GPU stack' => sub {
    my $r = add(project({ gpu => { enabled => JSON::PP::true(), driver => 'host',
                                   amd => { allocation => 'dra' } } }), gpu => 1);
    is $r->{rc}, 0, 'exit 0';
    is $r->{err}, '', 'nothing on STDERR';
    is_deeply $r->{steps}, [ 'kubeconfig (PIN1)', 'list OCPNodeProvider', 'get Deployment',
                             'SSH probe (PIN2)', 'write OCPNode', 'join (CLI)', 'GPU stack' ],
        'every step, in order' or diag explain $r->{steps};
};

# --- 5. through bin/ocp --------------------------------------------------------

# `ocp @args` in $dir as a user runs it: (stdout, stderr, exit code).
sub ocp_in {
    my ($dir, @args) = @_;
    my $tmp = path(tempdir(CLEANUP => 1));
    my ($out, $err) = map { $tmp->child($_) } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, @args or die "exec: $!";
    }
    waitpid $pid, 0;
    return ($out->slurp_utf8, $err->slurp_utf8, $? >> 8);
}

subtest 'bin/ocp node add --gpu: validate()\'s line on STDERR, exit 1, nothing written' => sub {
    my $dir = project({ gpu => { enabled => 'no' } });
    my @before = sort map { "$_" } $dir->children;
    my ($out, $err, $rc) = ocp_in($dir, 'node', 'add', 'brain', '--host', '10.0.0.5', '--gpu');
    is $rc, 1, 'exit 1';
    is $out, '', 'nothing on STDOUT';
    like $err, qr/\AError: ocp\.yaml has 1 error in its gpu: block:\n  - \Q$NO\E\n/,
        'STDERR: validate()\'s line' or diag $err;
    unlike $err, qr/kubeconfig/i, 'not the kubeconfig: the cluster was not asked for';
    is_deeply [ sort map { "$_" } $dir->children ], \@before, 'no file written in the project';
};

# --- 6. the lines are spec_errors('gpu') (k306) --------------------------------

# k306 step 2c: the refusal takes its lines from OCP::Config::spec_errors('gpu')
# instead of filtering all of validate() by /\Agpu[.:]/. On a mapping both are
# the same lines in the same order: held here on every gpu shape t/296 sweeps,
# alone and beside a line in every other section, where a line outside gpu:
# still holds nothing up. An ocp.yaml that is empty or no mapping is where they
# part: validate() has the file's line alone, the filter dropped it, and node
# add went on -- PIN1, the OCPNode, the join -- until a reader came to the spec.
# spec_errors stops with that line, so --gpu refuses it before anything.

# t/296's @SHAPES, at each key under gpu: t/296's sweep has.
my @VALUES = (
    [ "'foo'" => 'foo' ], [ '7' => 7 ], [ 'true' => JSON::PP::true() ], [ 'false' => JSON::PP::false() ],
    [ 'null' => undef ], [ '[]' => [] ], [ "['foo']" => [ 'foo' ] ], [ '[{}]' => [ {} ] ],
    [ '{}' => {} ], [ '{foo: bar}' => { foo => 'bar' } ],
);
my @GPU_AT = (
    [ 'gpu' => sub { +{ gpu => $_[0] } } ],
    (map { my $k = $_; [ "gpu.$k" => sub { +{ gpu => { $k => $_[0] } } } ] }
        qw( enabled driver toolkit amd enable )),
    (map { my $k = $_; [ "gpu.amd.$k" => sub { +{ gpu => { amd => { $k => $_[0] } } } } ] }
        qw( allocation resource_naming labeller metrics integrated alocation )),
);
# A line in every section but gpu:, the switches beside it among them.
my %ELSEWHERE = (name => [ 'a' ], control_planes => [ 'x' ], workers => [ 'x' ], kubernetes => 'foo',
                 network => 'foo', cilium => 'foo', system => 'foo', ssh => 'foo', robocop => 'foo',
                 lbipam => 'off', nocert => 'no');

subtest "spec_errors('gpu') is the filter's lines, on every gpu shape t/296 sweeps" => sub {
    my ($refused, $passed) = (0, 0);
    for my $at (@GPU_AT) {
        my ($path, $spec_with) = @$at;
        for my $v (@VALUES) {
            my ($shown, $value) = @$v;
            my $alone = $spec_with->($value);
            my @want  = gpu_lines(project($alone));
            for my $case ([ alone => $alone ], [ 'beside a line in every other section' => { %ELSEWHERE, %$alone } ]) {
                my ($beside, $spec) = @$case;
                my $what = "$path: $shown, $beside";
                my $dir  = project($spec);
                my $c    = config_of($dir);
                my @all  = $c->validate;
                ok scalar(grep { !/\Agpu[.:]/ } @all), "$what: validate() has lines outside gpu:"
                    if $beside ne 'alone';
                is_deeply [ $c->spec_errors('gpu') ], [ grep { /\Agpu[.:]/ } @all ], "$what: the filter's lines"
                    or diag explain \@all;
                is_deeply [ grep { /\Agpu[.:]/ } @all ], \@want, "$what: what it has alone";

                my $r = add($dir, gpu => 1);
                is_deeply { rc    => $r->{rc}, lines => [ $r->{err} =~ /^  - (.*)$/mg ],
                            steps => scalar @{ $r->{steps} } },
                    { rc => @want ? 1 : 0, lines => \@want, steps => @want ? 0 : 7 },
                    "$what: node add --gpu " . (@want ? 'refuses on them, nothing done' : 'goes on')
                    or diag explain [ @$r{qw( rc out err steps )} ];
            }
            @want ? $refused++ : $passed++;
        }
    }
    # Neither side of the sweep is empty: a shape refused, a shape that goes on.
    cmp_ok $refused, '>', 50, "refused: $refused shapes";
    cmp_ok $passed, '>', 10, "gone on: $passed shapes";
};

subtest 'an ocp.yaml that is empty or no mapping: --gpu refuses with its line, before anything' => sub {
    for my $case ([ 'empty' => '' ], [ 'a list' => "- name: k333\n" ], [ 'a string' => "foo\n" ]) {
        my ($what, $text) = @$case;
        my $dir = path(tempdir(CLEANUP => 1));
        $dir->child('ocp.yaml')->spew_utf8($text);
        my @all = config_of($dir)->validate;
        is scalar(@all), 1, "$what: validate() has one line" or diag explain \@all;
        like $all[0], qr/\A\Q$dir\E\/ocp\.yaml(?::| is empty:) /, "$what: the file's";

        for my $robocop (0, 1) {
            my $how = $robocop ? 'robocop path' : 'CLI path';
            my $r = add($dir, gpu => 1, robocop => $robocop, real_stack => 1);
            is $r->{rc}, 1, "$what, $how: exit 1";
            is_deeply $r->{steps}, [], "$what, $how: nothing done: no kubeconfig (PIN1), no cluster read or "
                . 'write, no SSH probe (PIN2), no join, no GPU stack' or diag explain $r->{steps};
            is $r->{out}, '', "$what, $how: nothing on STDOUT";
            is $r->{err}, "$all[0]\n", "$what, $how: STDERR is that line, alone";
        }

        # Unchanged: --nowait reads no gpu: key (section 4).
        is add($dir, gpu => 1, nowait => 1)->{rc}, 0, "$what: --gpu --nowait goes on";
    }
};

subtest 'bin/ocp node add --gpu on an ocp.yaml that is no mapping: its line, whatever the file is called' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8('');
    $dir->child('gpu.yaml')->spew_utf8("- name: k333\n");
    my @before = sort map { "$_" } $dir->children;
    my $what = 'a mapping (name, control_planes and the other settings)';
    for my $case ([ [], "ocp.yaml is empty: it must be $what" ],
                  [ [ '-c', 'gpu.yaml' ], "gpu.yaml: must be $what, not a list" ]) {
        my ($c, $line) = @$case;
        my ($out, $err, $rc) = ocp_in($dir, @$c, 'node', 'add', 'brain', '--host', '10.0.0.5', '--gpu');
        is $rc, 1, "$line: exit 1";
        is $out, '', "$line: nothing on STDOUT";
        is $err, "Error: $line\n", "$line: STDERR is the line, and not a gpu: block's";
    }
    is_deeply [ sort map { "$_" } $dir->children ], \@before, 'no file written in the project';
};

done_testing;
