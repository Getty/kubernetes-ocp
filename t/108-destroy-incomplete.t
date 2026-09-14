#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Cmd::Destroy;

#
# karr k140: `ocp destroy` downgraded a failed provider delete to a STDERR
# warning, then ran _cleanup_project_state UNCONDITIONALLY -- deleting
# .ocp/status.yaml -- and finished with "Cluster destroyed." and exit 0.
#
# The Hetzner server whose delete failed (rate-limit, transient 5xx, a locked
# server, a reduced-scope token) keeps running and keeps billing, but
# status.yaml -- the only local record of its providerId -- is gone, so a
# re-run has no handle to find and delete it. This is exactly the money-losing
# failure the module's key handling (execute(), "never let a cleanup step cost
# someone money") is at pains to avoid, in the one place it was not guarded.
#
# A teardown where any provider delete fails must: keep status.yaml (with the
# failed node's providerId) intact, report the teardown as INCOMPLETE naming
# the surviving node(s), and exit non-zero. The all-succeeded path is
# unchanged (t/107 covers the STDOUT/STDERR channels for it).
#

# ------------------------------------------------------------- capture helper

# Both channels to their own in-memory scalar, so the incompleteness diagnosis
# (STDERR) and the progress narrative (STDOUT) can be asserted apart, and the
# execute() return value comes back for the exit-code assertion.
sub capture (&) {
    my ($code) = @_;
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die "capture stdout: $!";
    open my $efh, '>', \$err or die "capture stderr: $!";
    local *STDOUT = $ofh;
    local *STDERR = $efh;
    my @ret = eval { $code->() };
    my $ex  = $@;
    close $ofh;
    close $efh;
    return { out => $out, err => $err, ex => $ex, ret => \@ret };
}

# ------------------------------------------------------------- stubs

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

# A Hetzner provider stand-in whose delete_server dies for one nominated
# providerId and succeeds for the rest -- a partial teardown failure, the
# realistic shape (one server locked/rate-limited among several).
{
    package FakeHetzner;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster { [] }
    sub delete_server {
        my ($self, $id) = @_;
        die "hetzner delete failed for $id\n"
            if defined $self->{die_on_id} && $id eq $self->{die_on_id};
        push @{ $self->{deleted} }, $id;
        return 1;
    }
}

sub project {
    my ($status) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n");
    $dir->child('.ocp', 'status.yaml')->spew_utf8($status);
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

my $STATUS = <<'YAML';
nodes:
  - name: police1
    provider: hetzner
    providerId: "111"
    public_ip: 1.1.1.1
  - name: police2
    provider: hetzner
    providerId: "222"
    public_ip: 2.2.2.2
YAML

sub run_destroy {
    my ($config, %opt) = @_;
    my @deleted;
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,
    );
    my $fake = FakeHetzner->new(die_on_id => $opt{die_on_id}, deleted => \@deleted);
    my $r = capture {
        no warnings 'redefine';
        local *OCP::Secrets::hetzner_token = sub { 'tok' };
        local *OCP::Provider::for_spec     = sub { $fake };
        $cmd->execute([], []);
    };
    $r->{deleted} = \@deleted;
    return $r;
}

subtest 'a failed delete keeps status.yaml, reports incomplete, exits non-zero' => sub {
    my $config      = project($STATUS);
    my $status_file = $config->status_file;
    ok -f $status_file, 'status.yaml exists before destroy';

    my $r = run_destroy($config, die_on_id => '222');

    is $r->{ex}, '', 'ran without dying (a failed delete is not fatal)'
        or diag $r->{err};

    # (a) status.yaml retained, still holding the failed node's providerId
    ok -f $status_file, 'status.yaml is NOT deleted when a delete failed';
    like +(-f $status_file ? path($status_file)->slurp_utf8 : ''), qr/222/,
        'the failed node providerId is still recorded so a re-run can find it';

    # (b) non-zero exit
    is $r->{ret}[0], 1, 'execute returns a non-zero exit code';

    # (c) the final human message says the teardown was incomplete and names
    #     the failed node -- on STDERR, per the output-channel rule.
    like $r->{err}, qr/INCOMPLETE/i, 'teardown is reported as incomplete';
    like $r->{err}, qr/police2/,     'the surviving node is named';
    unlike $r->{out}, qr/Cluster destroyed/,
        'the misleading "Cluster destroyed." success line is gone from STDOUT';

    # the reachable sibling really was deleted -- a partial failure still tears
    # down what it can.
    is_deeply [sort @{ $r->{deleted} }], ['111'],
        'the reachable node was still deleted';
};

subtest 'the all-succeeded path is unchanged' => sub {
    my $config      = project($STATUS);
    my $status_file = $config->status_file;

    my $r = run_destroy($config, die_on_id => undef);

    is $r->{ex}, '', 'ran without dying';
    like $r->{out}, qr/Cluster destroyed/, 'success line still printed on STDOUT';
    is $r->{ret}[0], 0, 'execute returns 0';
    ok !-f $status_file, 'status.yaml is removed on a clean teardown';
    is_deeply [sort @{ $r->{deleted} }], ['111', '222'], 'both nodes deleted';
};

done_testing;
