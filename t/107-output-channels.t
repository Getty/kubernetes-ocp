#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny qw(path);

use lib 'lib';

use OCP;
use OCP::Config;
use OCP::Cmd::Destroy;
use OCP::Cmd::SSH;

#
# karr #105: the STDOUT/STDERR channel rule.
#
# The rule (.claude/rules/ocp-rules.md, "Output channels — STDOUT vs STDERR):
#   STDOUT is the payload or the progress report a human reads; STDERR is
#   everything that went wrong, with its diagnosis. A command whose payload is
#   machine-readable (or, like `ocp ssh`, delegated to an exec'd session that
#   inherits STDOUT) puts ONLY the payload on STDOUT.
#
# OCP::Cmd::Destroy and OCP::Cmd::SSH were the two named outliers: both wrote
# diagnoses to STDOUT. This test locks the corrected channels so a regression
# that pushes a warning back onto STDOUT — where it would pollute a pipe — is
# a red test, not a silent drift.
#

# ------------------------------------------------------------- capture helper

# Runs $code with STDOUT and STDERR each redirected to an in-memory scalar,
# so both channels can be asserted independently. Localising the globs makes
# both bare `print` (STDOUT) and `print STDERR` land in their own buffer.
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

{
    package FakeServer;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub name { $_[0]{name} }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

# A Hetzner provider stand-in. delete_server can be told to die, so the
# "  Warning: ..." diagnosis path is deterministic and network-free.
{
    package FakeHetzner;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        return $self->{by_cluster}{$label} // [];
    }
    sub delete_server {
        my ($self, $id) = @_;
        die "hetzner delete failed\n" if $self->{die_on_delete};
        return 1;
    }
}

sub project {
    my ($name, $yaml_extra, %files) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: $name\n" . ($yaml_extra // ''));
    for my $rel (keys %files) {
        my $f = $dir->child(split m{/}, $rel);
        $f->parent->mkpath;
        $f->spew_utf8($files{$rel});
    }
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub destroy_cmd {
    my ($config) = @_;
    return OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        force         => 1,
    );
}

# ============================================================ ocp destroy

subtest 'destroy: a clean run keeps STDERR empty' => sub {
    # No nodes, no Hetzner token: the early "No nodes to destroy." return.
    # A successful command must say nothing on STDERR.
    my $config = project('empty');
    my $cmd    = destroy_cmd($config);

    my $r = capture {
        no warnings 'redefine';
        local *OCP::Secrets::hetzner_token = sub { undef };
        $cmd->execute([], []);
    };

    is $r->{ex}, '', 'ran without dying';
    like $r->{out}, qr/No nodes to destroy/, 'progress went to STDOUT';
    is   $r->{err}, '', 'nothing on STDERR for a clean run';
};

subtest 'destroy: a delete failure is diagnosed on STDERR, not STDOUT' => sub {
    # A hetzner node recorded in status.yaml whose delete_server dies. The
    # progress narrative ("Deleting ...") stays on STDOUT; both the "Warning:"
    # diagnosis and the "teardown INCOMPLETE" summary move to STDERR -- a
    # failed teardown's result line is a diagnosis, not payload. There is no
    # "Cluster destroyed." here: that line is printed only on a clean run
    # (k140), and pushing it out over a failed delete was the money-losing bug.
    my $config = project('prod', '', '.ocp/status.yaml' => <<'YAML');
nodes:
  - name: police1
    provider: hetzner
    providerId: "999"
    public_ip: 1.2.3.4
YAML

    my $cmd = destroy_cmd($config);
    my $fake = FakeHetzner->new(die_on_delete => 1);

    my $r = capture {
        no warnings 'redefine';
        local *OCP::Secrets::hetzner_token = sub { 'tok' };
        local *OCP::Provider::for_spec     = sub { $fake };
        $cmd->execute([], []);
    };

    is $r->{ex}, '', 'ran without dying (a failed delete is a warning, not fatal)';

    like $r->{out}, qr/Deleting police1/,   'the delete step is announced on STDOUT';
    unlike $r->{out}, qr/Cluster destroyed/, 'no false success line on STDOUT';
    unlike $r->{out}, qr/Warning/,          'the warning does NOT pollute STDOUT';
    unlike $r->{out}, qr/INCOMPLETE/,       'the incompleteness diagnosis stays off STDOUT';

    like $r->{err}, qr/Warning:.*hetzner delete failed/s,
        'the failure diagnosis is on STDERR';
    like $r->{err}, qr/INCOMPLETE/,
        'the "teardown incomplete" summary is on STDERR too';
};

subtest 'destroy: mislabelled-server report is a STDERR diagnosis' => sub {
    # _report_mislabelled_servers warns that paid servers were NOT deleted —
    # a diagnosis about something wrong, so it belongs on STDERR.
    my $config = project('prod', <<'YAML');
control_planes:
  - provider: hetzner
YAML

    my $cmd  = destroy_cmd($config);
    my $fake = FakeHetzner->new(
        by_cluster => {
            'hetzner-default' => [
                FakeServer->new(name => 'stray1', id => '1', ipv4 => '5.6.7.8'),
            ],
        },
    );

    my $r = capture { $cmd->_report_mislabelled_servers($config, $fake) };

    is   $r->{out}, '', 'STDOUT stays clean of the mislabelled-server warning';
    like $r->{err}, qr/carry the label ocp-cluster=hetzner-default/,
        'the "not deleted, still billing" diagnosis is on STDERR';
    like $r->{err}, qr/stray1/, 'the offending server is named on STDERR';
};

# ============================================================ ocp ssh

subtest 'ssh: the API-lookup progress note goes to STDERR' => sub {
    # `ocp ssh` execs into the interactive session, which inherits STDOUT, so
    # every line ocp itself prints is preamble that must not land on STDOUT.
    # _resolve_target_host's "Looking up ..." note is the reachable-without-
    # exec proof of that.
    my $config = project('c', <<'YAML');
control_planes:
  - provider: hetzner
YAML
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    my $ssh     = OCP::Cmd::SSH->new(node => 'police1');

    my $r = capture {
        $ssh->_resolve_target_host($config, $secrets, 'police1');
    };

    is   $r->{out}, '', 'STDOUT is left clean for the interactive session';
    like $r->{err}, qr/Looking up control plane IP/,
        'the progress note is on STDERR';
};

subtest 'ssh: no bare STDOUT output survives in the source' => sub {
    # Cheap regression guard, in the style of t/77-destroy-local-provider:
    # every print/printf in OCP::Cmd::SSH must name STDERR. A bare `print "`
    # would put ocp's framing back onto the session's STDOUT.
    my $src = path('lib/OCP/Cmd/SSH.pm')->slurp_utf8;

    # Strip the POD/synopsis tail so the `ocp ssh ...` examples there are not
    # mistaken for print statements.
    $src =~ s/^__END__.*//ms;

    unlike $src, qr/\bprint\s+"/,  'no bare `print "..."` (STDOUT) remains';
    unlike $src, qr/\bprintf\s+"/, 'no bare `printf "..."` (STDOUT) remains';
};

done_testing;
