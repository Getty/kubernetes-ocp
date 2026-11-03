#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw( tempdir );
use FindBin;
use JSON::PP ();
use Path::Tiny qw( path );
use YAML::XS ();

BEGIN { $ENV{ANSI_COLORS_DISABLED} = 1 }

use lib 'lib';
use OCP;
use OCP::Choices;
use OCP::Config;
use OCP::Cmd::Status;
use OCP::Cmd::Update;
use OCP::Rex;
use OCP::Robocop::Manifest;

#
# k379: network:, cilium:, registry: and ssl: were read as they stood, and the
# accessors that did refuse a wrong shape croaked.
#
# The claims here:
#   1. a network:, cilium:, registry: or ssl: that is no mapping is one line
#      of validate(), and every accessor that reads the section refuses it in
#      that line: the line and a newline, nothing else. registry: and ssl: had
#      no line at all, and a string there died inside Perl;
#   2. a key of registry: or ssl: that is no string is a line too, refused the
#      same way -- the shape ssh: has (k340). A string passes and reads as
#      before;
#   3. a sweep puts every YAML shape at the four sections, and at each key of
#      registry: and ssl:: validate() never dies, and each reader either
#      refuses in the lines validate() says about what it reads, or reads on.
#      What is wrong inside network: and cilium: stays validate()'s alone;
#   4. every accessor that refuses dies with one line and a newline, never a
#      croak's " at FILE line N.": OCP::run_cli called that an internal
#      error, about a line of the user's ocp.yaml;
#   5. through the commands that read without validate() first -- the
#      robocop Deployment's settings (ocp deploy-robocop, ocp deploy-image),
#      ocp status' AMD allocation warning -- and ocp apply --dry-run for
#      registry: and ssl:, which nothing reads before validate(): the line,
#      and no Perl text. ocp update checks what it reads before it runs
#      (k400): network:, cilium: and gpu: false stop it with the line in
#      OCP::Role::Cmd's one text, before any component -- it upgraded
#      cert-manager first (k394). Drift's refused-switch entry has its own
#      test (t/332).
#

my $PERL_TEXT = qr/ at \S+ line \d+|internal error|HASH\(0x|ARRAY\(0x/;

local @ARGV = ();
my $ocp    = OCP->new;
my $tmpdir = tempdir(CLEANUP => 1);
my $bin    = "$FindBin::Bin/../bin/ocp";
my $lib    = "$FindBin::Bin/../lib";

# Through a file, as ocp reads it: YAML booleans come back as JSON::PP::Boolean.
sub config_for {
    my ($spec) = @_;
    my $f = path($tmpdir)->child('c' . int(rand(1_000_000)) . '.yaml');
    $f->spew_utf8(YAML::XS::Dump({ name => 'k379', control_planes => { provider => 'local' }, %$spec }));
    return OCP::Config->new(file => $f->stringify, ocp => $ocp);
}

my @SHAPES = (
    [ "'foo'" => 'foo' ], [ '7' => 7 ], [ 'true' => JSON::PP::true ], [ 'false' => JSON::PP::false ],
    [ 'null' => undef ], [ '[]' => [] ], [ "['foo']" => [ 'foo' ] ], [ '{}' => {} ],
    [ '{foo: bar}' => { foo => 'bar' } ],
);
my @NOT_A_MAPPING = grep { my $v = $_->[1]; defined $v && ref $v ne 'HASH' } @SHAPES;

# A value as a line quotes it: a scalar in quotes, a boolean as YAML writes
# it, a list or a mapping by name.
sub shown {
    my ($v) = @_;
    return JSON::PP::is_bool($v) ? ($v ? 'true' : 'false')
         : ref $v eq 'ARRAY'     ? 'a list'
         : ref $v eq 'HASH'      ? 'a mapping'
         :                         "'$v'";
}

# Every accessor that reads the section, and validate()'s line for a value
# that is no mapping.
my %READERS = (
    network  => [ qw( network_config pod_cidr pod_cidr_is_set lb_pool_config lb_pool_blocks
                      l2_config l2_node_selector l2_interfaces ) ],
    cilium   => [ qw( cilium_config cilium_helm_values ) ],
    registry => [ qw( registry_config registry_cache registry_upstream registry_name
                      has_external_cache has_external_upstream ) ],
    ssl      => [ qw( ssl_config ssl_email ) ],
);
my %SHAPE_LINE = (
    network  => sub { 'network: must be a mapping' },
    cilium   => sub { 'cilium: must be a mapping (devices, helm_values)' },
    registry => sub { "registry: must be a mapping (cache, upstream, name), not $_[0]" },
    ssl      => sub { "ssl: must be a mapping (email), not $_[0]" },
);
# The keys of registry: and ssl:, each one string, and what the line calls it.
my %STRING_KEYS = (
    registry => [ [ cache    => 'a URL like http://cache.example:5000' ],
                  [ upstream => 'a URL like http://registry.example:5000' ],
                  [ name     => 'a host name like ocp.internal' ] ],
    ssl      => [ [ email    => 'an address like admin@example.com' ] ],
);

is_deeply [ config_for({})->validate ], [], 'the fixture: the bare config passes';

# --- 1. a section that is no mapping ----------------------------------------

for my $section (sort keys %READERS) {
    subtest "$section: a value that is no mapping is validate()'s line, and every reader's" => sub {
        for my $shape (@NOT_A_MAPPING) {
            my ($shown, $value) = @$shape;
            my $line = $SHAPE_LINE{$section}->(shown($value));
            my $c = config_for({ $section => $value });
            is_deeply [ $c->validate ], [ $line ], "$section: $shown -- validate(), one line";
            for my $m (@{ $READERS{$section} }) {
                ok !eval { $c->$m; 1 }, "$m refuses $section: $shown";
                is $@, "$line\n", "$m: validate()'s line and a newline, no Perl location";
            }
        }
    };
}

# --- 2. a key of registry: or ssl: that is no string -------------------------

for my $section (sort keys %STRING_KEYS) {
    subtest "$section: a key that is no string is a line, refused by every reader" => sub {
        for my $key (@{ $STRING_KEYS{$section} }) {
            my ($k, $what) = @$key;
            for my $shape (grep { ref $_->[1] } @SHAPES) {
                my ($shown, $value) = @$shape;
                my $line = "$section.$k: must be a string ($what), not " . shown($value);
                my $c = config_for({ $section => { $k => $value } });
                is_deeply [ $c->validate ], [ $line ], "$section.$k: $shown -- validate(), one line";
                for my $m (@{ $READERS{$section} }) {
                    ok !eval { $c->$m; 1 }, "$m refuses $section.$k: $shown";
                    is $@, "$line\n", "$m: validate()'s line and a newline";
                }
            }
        }
        my %set = map { $_->[0] => "http://$_->[0].k379.test:5000" } @{ $STRING_KEYS{$section} };
        my $c = config_for({ $section => \%set });
        is_deeply [ $c->validate ], [], "$section: strings pass";
        is_deeply $c->${\ "${section}_config" }, \%set, "${section}_config reads them";
    };
}

subtest 'registry: and ssl: read as before' => sub {
    my $c = config_for({ registry => { cache => 'http://c.k379.test:5000', upstream => 'http://u.k379.test:5000',
                                       name => 'reg.k379.test' },
                         ssl      => { email => 'ops@k379.test' } });
    is $c->registry_cache,    'http://c.k379.test:5000', 'registry_cache';
    is $c->registry_upstream, 'http://u.k379.test:5000', 'registry_upstream';
    is $c->registry_name,     'reg.k379.test',           'registry_name';
    ok $c->has_external_cache && $c->has_external_upstream, 'both external';
    is $c->ssl_email, 'ops@k379.test', 'ssl_email';

    my $none = config_for({});
    is $none->registry_name, 'ocp.internal', 'registry_name: the default';
    ok !$none->has_external_cache && !$none->has_external_upstream, 'nothing external';
    is $none->ssl_email, '', 'ssl_email: none';
};

# --- 3. the sweep -------------------------------------------------------------

my @AT = (
    (map { my $s = $_; [ $s => sub { +{ $s => $_[0] } } ] } sort keys %READERS),
    (map { my $s = $_; map { my $k = $_->[0];
        [ "$s.$k" => sub { +{ $s => { $k => $_[0] } } } ] } @{ $STRING_KEYS{$s} } } sort keys %STRING_KEYS),
);

subtest 'every shape at each: refused in the lines validate() says about it, or read on' => sub {
    for my $at (@AT) {
        my ($path, $spec_with) = @$at;
        (my $section = $path) =~ s/\..*//;
        for my $shape (@SHAPES) {
            my ($shown, $value) = @$shape;
            my $c = config_for($spec_with->($value));
            my @lines;
            ok eval { @lines = $c->validate; 1 }, "$path: $shown -- validate() does not die" or diag $@;
            # The section's own shape, or (registry:, ssl:) a key that is no
            # string: what the readers refuse on. An unknown key under
            # network: or cilium: is no reader's business.
            my @refused = grep { /\A\Q$section\E(?::|\.\w+: must be a string )/ } @lines;
            @refused = grep { /\A\Q$section\E: / } @refused unless $STRING_KEYS{$section};
            for my $m (@{ $READERS{$section} }) {
                my $ok = eval { $c->$m; 1 };
                if (@refused) {
                    ok !$ok, "$m, $path: $shown -- refused";
                    is $@, join('; ', @refused) . "\n", "$m, $path: $shown -- in validate()'s words";
                }
                else {
                    is $@, '', "$m, $path: $shown -- reads on";
                }
            }
        }
    }
};

# --- 4. every refusing accessor: a line and a newline -------------------------

# One spec each that the accessor refuses. Most refuse in validate()'s very
# line (t/296 holds each to it); what all of them owe is a message
# OCP::run_cli prints as the user's error, not as an internal one.
my @REFUSING = (
    [ kubernetes             => { kubernetes => 'k3s' } ],
    [ kubernetes             => { kubernetes => { distribution => 'k3s' } } ],
    [ distribution           => { kubernetes => { dist => 'rke3' } } ],
    [ version                => { kubernetes => { version => [ 'v1' ] } } ],
    [ ssh_config             => { ssh => 'id_ed25519' } ],
    [ ssh_private_key_path   => { ssh => { private_key => [ 'a' ] } } ],
    [ system_config          => { system => 'utc' } ],
    [ timezone               => { system => { time_zone => 'UTC' } } ],
    [ robocop_enabled        => { robocop => 'no' } ],
    [ robocop_security_level => { robocop => { security_level => 'secrets' } } ],
    [ robocop_image          => { robocop => { image => 'ocp' } } ],
    [ lbipam                 => { lbipam => 'no' } ],
    [ no_cert                => { nocert => 'off' } ],
    [ ntp_enabled            => { system => { ntp => 'yes' } } ],
    [ gpu_config             => { gpu => JSON::PP::false } ],
    [ gpu_enabled            => { gpu => { enable => JSON::PP::false } } ],
    [ gpu_toolkit            => { gpu => { toolkit => 'no' } } ],
    [ gpu_driver             => { gpu => { driver => 'nvidia' } } ],
    [ gpu_amd_config         => { gpu => { amd => 'dra' } } ],
    [ gpu_amd_config         => { gpu => { amd => { alocation => 'dra' } } } ],
    [ gpu_amd_allocation     => { gpu => { amd => { allocation => JSON::PP::true } } } ],
    [ gpu_amd_resource_naming => { gpu => { amd => { resource_naming => 'many' } } } ],
    [ gpu_amd_labeller       => { gpu => { amd => { labeller => 'off' } } } ],
    [ cluster_status         => { control_planes => { provider => 'ssh', host => [ 'cp.k379.test' ] } } ],
    [ join_host              => { control_planes => { provider => 'local', public_ip => [ '10.9.0.1' ] } } ],
    (map { [ $READERS{$_}[0] => { $_ => 'foo' } ] } sort keys %READERS),
);

subtest 'every refusing accessor dies with one line and a newline, no Perl location' => sub {
    for my $r (@REFUSING) {
        my ($m, $spec) = @$r;
        my $what = "$m on " . JSON::PP->new->canonical->allow_nonref->allow_blessed->convert_blessed->encode($spec);
        my $c = config_for($spec);
        ok !eval { $m eq 'join_host' ? $c->join_host('adv.k379.test') : $c->$m; 1 }, "$what -- refused";
        my $err = $@;
        like $err, qr/\A[^\n]+\n\z/, "$what -- one line and a newline";
        unlike $err, $PERL_TEXT, "$what -- no Perl text";
        my ($msg, $internal) = OCP::_clean_message($err);
        is $internal, 0, "$what -- not an internal error to OCP::run_cli";
        is "$msg\n", $err, "$what -- printed as it is";
    }
};

# --- 5. through the commands --------------------------------------------------

{
    package FakeOcp;
    sub new     { my ($class, %args) = @_; bless {%args}, $class }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# A deployed dev-mode project (t/94's): kubeconfig.yaml, a status file stamped
# with this OCP, the bootstrap key. $extra goes into ocp.yaml as it is.
sub project {
    my ($extra) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8(
        "name: updatetest\ncontrol_planes:\n  provider: hetzner\n  public_ip: 1.2.3.4\n$extra");
    $dir->child('kubeconfig.yaml')->spew_utf8("encrypted-placeholder\n");
    $dir->child('.ocp', 'id_ed25519')->spew_utf8("-----BEGIN OPENSSH PRIVATE KEY-----\nBOOT\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8(<<"YAML");
ocpVersion: '$OCP::VERSION'
nodes:
  - name: police1
    provider: hetzner
    public_ip: 1.2.3.4
YAML
    return $dir;
}

# `ocp update --force` in process, Rex and the cluster API replaced by
# recorders (t/94's). Returns exit code, STDOUT, STDERR, the tasks run, and
# what execute died with.
sub run_update {
    my ($dir, %opt) = @_;
    my @tasks;
    my ($out, $err, $rc, $died) = ('', '');
    {
        no warnings 'redefine';
        local *OCP::Rex::new = sub { my ($c, %a) = @_; bless {%a}, $c };
        local *OCP::Rex::run_task = sub { push @tasks, $_[1]; return 1 };
        local *OCP::Cmd::Update::_update_via_api = sub { push @tasks, $_[4]; return 1 };
        my $cmd = OCP::Cmd::Update->new(
            command_chain => [ FakeOcp->new(config => $dir->child('ocp.yaml')->stringify) ],
            force => 1, %opt,
        );
        local *STDOUT;
        local *STDERR;
        open STDOUT, '>', \$out or die $!;
        open STDERR, '>', \$err or die $!;
        $rc = eval { $cmd->execute([], []) };
        $died = $@;
    }
    return ($rc, $out, $err, \@tasks, $died);
}

subtest 'ocp update: the fixture upgrades Cilium' => sub {
    my ($rc, $out, $err, $tasks, $died) = run_update(project(''));
    is $died, '', 'no die';
    is $rc, 0, 'exit 0' or diag "OUT:\n$out\nERR:\n$err";
    is_deeply $tasks, [qw( upgrade_cert_manager upgrade_cilium )], 'cert-manager, then Cilium';
};

for my $case (
    [ 'network: foo' => "network: foo\n", 'network: must be a mapping' ],
    [ 'cilium: foo'  => "cilium: foo\n",  'cilium: must be a mapping (devices, helm_values)' ],
) {
    my ($name, $yaml, $line) = @$case;
    subtest "ocp update, $name: refused before any component, with the line" => sub {
        my $dir = project($yaml);
        my ($rc, $out, $err, $tasks, $died) = run_update($dir);
        my $file = $dir->child('ocp.yaml')->stringify;
        is $died, "$file has 1 error:\n  - $line\n"
            . "Nothing was done: ocp update checks what it reads of $file before it asks for a PIN "
            . "or touches the cluster or a machine. Fix the line above and run it again.\n",
            'refused with the line, in the one text';
        is $out . $err, '', 'nothing said besides';
        unlike $died, $PERL_TEXT, 'no Perl text';
        is_deeply $tasks, [], 'no component upgraded, cert-manager neither';
    };
}

# The real CLI, as a user runs it: gpu: false stops ocp update before its
# plan, in OCP::Role::Cmd's check (k400; it stopped at the plan, outside any
# eval, before), and OCP::run_cli prints what it died with.
subtest 'ocp update --dry-run, gpu: false: the line, not "internal error"' => sub {
    my $dir = project("gpu: false\n");
    my ($out, $err) = map { $dir->parent->child("k379-$$-$_") } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, 'update', '--dry-run', '--force' or die "exec: $!";
    }
    waitpid $pid, 0;
    my $rc = $? >> 8;
    my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);
    $_->remove for $out, $err;

    is $rc, 1, 'exit 1';
    is $e, "Error: ocp.yaml has 1 error:\n  - gpu: must be a mapping, not false; write gpu: { enabled: false }\n"
         . "Nothing was done: ocp update checks what it reads of ocp.yaml before it asks for a PIN "
         . "or touches the cluster or a machine. Fix the line above and run it again.\n",
        'STDERR: validate()\'s line, in the one text, nothing else';
    unlike $o . $e, $PERL_TEXT, 'no Perl text';
    unlike $o, qr/Updates planned/, 'no plan printed';
};

# ocp deploy-robocop and ocp deploy-image send these with the Deployment.
subtest "the robocop Deployment's settings, network: foo: the line" => sub {
    my $c = config_for({ network => 'foo' });
    ok !eval { OCP::Robocop::Manifest->cluster_env($c); 1 }, 'cluster_env refuses';
    is $@, "network: must be a mapping\n", "validate()'s line";
    is_deeply(OCP::Robocop::Manifest->cluster_env(config_for({ network => { pod_cidr => '10.60.0.0/16' } })),
        [ { name => 'OCP_DISTRIBUTION', value => 'rke2' }, { name => 'OCP_POD_CIDR', value => '10.60.0.0/16' } ],
        'a mapping reads as before');
};

subtest "ocp status, a gpu.amd.allocation it refuses: one WARNING line" => sub {
    my $c = config_for({ gpu => { amd => { allocation => JSON::PP::true } } });
    my $err = '';
    my $got;
    {
        local *STDERR;
        open STDERR, '>', \$err or die $!;
        $got = OCP::Cmd::Status->_amd_gpu_default_allocation($c);
    }
    is $got, undef, 'no allocation';
    is $err, 'WARNING: gpu.amd.allocation must be '
        . OCP::Choices::or_list(@OCP::Config::GPU_AMD_ALLOCATIONS) . ', not true; AMD nodes without their own '
        . "$OCP::Config::AMD_GPU_ALLOCATION_LABEL label show their allocation as unknown\n",
        'the line, in one WARNING line';
};

# k363: the cause is said by OCP::ErrorLine::one_line. The hand-made strip took
# one location off the very end only, so a refusal that carried one in the
# middle -- validate()'s lines joined with '; ', a die that wraps another --
# kept it, and its newline, inside the WARNING line.
subtest "ocp status, a gpu.amd.allocation refusal with a location inside: still one WARNING line" => sub {
    {
        package Local::K363::WrappedRefusal;
        sub new { bless {}, shift }
        sub gpu_amd_allocation {
            die "gpu.amd: cannot read it: Not a HASH reference at lib/OCP/Config.pm line 1046.\n"
              . "write gpu.amd: as a mapping\n";
        }
    }
    my $err = '';
    my $got;
    {
        local *STDERR;
        open STDERR, '>', \$err or die $!;
        $got = OCP::Cmd::Status->_amd_gpu_default_allocation(Local::K363::WrappedRefusal->new);
    }
    is $got, undef, 'no allocation';
    is $err, 'WARNING: gpu.amd: cannot read it: Not a HASH reference write gpu.amd: as a mapping;'
        . " AMD nodes without their own $OCP::Config::AMD_GPU_ALLOCATION_LABEL label show their"
        . " allocation as unknown\n",
        'one WARNING line, without the location in the middle';
};

# Nothing reads registry: or ssl: before validate(): ocp apply refuses them
# first, with the other lines. workers: none is one of those, so the run ends
# at validate() whatever it says about the other two.
subtest 'ocp apply --dry-run, registry: and ssl: of the wrong shape: the lines on STDERR, exit 1' => sub {
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('ocp.yaml')->spew_utf8(YAML::XS::Dump({
        name => 'k379', control_planes => { provider => 'local' },
        registry => 'cache.k379.test', ssl => { email => [ 'ops@k379.test' ] }, workers => 'none',
    }));
    my ($out, $err) = map { $dir->parent->child("k379-$$-$_") } qw( out err );
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        open STDIN,  '<', '/dev/null' or die;
        open STDOUT, '>', "$out"      or die;
        open STDERR, '>', "$err"      or die;
        exec $^X, "-I$lib", $bin, 'apply', '--dry-run' or die "exec: $!";
    }
    waitpid $pid, 0;
    my $rc = $? >> 8;
    my ($o, $e) = ($out->slurp_utf8, $err->slurp_utf8);
    $_->remove for $out, $err;

    is $rc, 1, 'exit 1';
    is $o, '', 'nothing on STDOUT';
    like $e, qr/\AError: ocp\.yaml has 3 errors:\n/, 'the refusal, counted';
    like $e, qr/^  - workers: must be a list/m, 'workers';
    like $e, qr/^  - registry: must be a mapping \(cache, upstream, name\), not 'cache\.k379\.test'$/m, 'registry';
    like $e, qr/^  - ssl\.email: must be a string \(an address like admin\@example\.com\), not a list$/m, 'ssl.email';
    unlike $e, $PERL_TEXT, 'no Perl text';
};

done_testing;
