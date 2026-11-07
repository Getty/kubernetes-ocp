#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use JSON::MaybeXS qw(encode_json);
use Path::Tiny qw(path);
use POSIX ();

# Absolute, so a module required after a child's chdir into its project is
# still this tree's.
use lib "$FindBin::Bin/../lib";

use Kubernetes::REST::APIError;
use WWW::Hetzner::HTTPResponse;
use WWW::Hetzner::LWPIO;

use OCP;
use OCP::ClusterKey;
use OCP::Cmd::Destroy;
use OCP::Config;
use OCP::Keys;
use OCP::Password;
use OCP::Provider::Local;
use OCP::Provider::SSH;
use OCP::Secrets;

#
# k396: what `ocp destroy` still skipped without a word, or said raw, after
# k353, k363 and k399. What it skips or cannot reach goes to STDERR with its
# diagnosis; STDOUT stays the progress report and claims nothing it did not
# check.
#
# The claims:
#   1. an ssh node with no host recorded -- in .ocp/status.yaml, or as an
#      OCPNode -- was skipped at the uninstall without a word. It is said on
#      STDERR and named in the closing list; the run exits 1;
#   2. the search for servers under the old <type>-default label swallowed a
#      failure: it is said, with its cause, the selector, and exit 1;
#   3. with one token's label search answering and another's failing, the
#      control-plane fallback said on STDOUT that no server carries the
#      label: it says only what the answering search found;
#   4. errors said raw, a Perl source location on them, are one line: why an
#      OCPNodeProvider gave no Hetzner adapter, why the OCPNodes could not be
#      read; and an uninstall's failure keeps its lines, without one;
#   5. the SSH key's refusal of several lines keeps its lines, without the
#      ERROR: label, instead of one long line;
#   6. the project key for the SSH key is asked, or checked, before the
#      lookup's eval: a wrong PIN1 there, or a broken SOPS_AGE_KEY_FILE,
#      stops the run before anything is deleted, in OCP::Secrets' words. With
#      no one to ask PIN1 is not asked, and a wrong PIN2 is still the
#      downgrade it was;
#   7. (k382, untested until here) a broken SOPS_AGE_KEY_FILE stops destroy
#      before anything is listed with HETZNER_API_TOKEN set, as without it.
#
# 1-5 run execute in-process with every provider and the cluster API faked;
# 6 and 7 run `ocp destroy` through bin/ocp's run_cli in a child, with only
# the Hetzner wire faked (as t/382). Nothing is ever deleted for real.
#

no warnings 'once';

is path($INC{'OCP/Cmd/Destroy.pm'})->realpath->stringify,
   path("$FindBin::Bin/../lib/OCP/Cmd/Destroy.pm")->realpath->stringify,
   'the Destroy.pm under test is this tree\'s';

umask 022;
delete local $ENV{SOPS_AGE_KEY_FILE};
delete local $ENV{KUBECONFIG};

# ============================================================== in-process

{
    package FakeOcp;
    sub new     { my ($c, %a) = @_; bless {%a}, $c }
    sub verbose { 0 }
    sub config  { $_[0]{config} }
}

my @events;

# Servers by label; the error a label search dies with, by "label token";
# the error an uninstall dies with, by host; the error from_cr dies with, by
# OCPNodeProvider name.
my (%labelled, %search_dies, %delete_dies, %from_cr_dies);

{
    package FakeServer;
    sub new  { my ($c, %a) = @_; bless {%a}, $c }
    sub name { $_[0]{name} }
    sub id   { $_[0]{id} }
    sub ipv4 { $_[0]{ipv4} }
}

{
    package FakeProvider;
    sub new   { my ($c, %a) = @_; bless {%a}, $c }
    sub token { $_[0]{token} }
    sub list_servers_by_cluster {
        my ($self, $label) = @_;
        my $token = $self->token // '';
        push @events, [ search => "$label", $token ];
        my $dies = $search_dies{"$label $token"};
        die $dies if defined $dies;
        return [ map { FakeServer->new(%$_) } @{ $labelled{$label} // [] } ];
    }
    sub resolve_host {
        my ($self, %opts) = @_;
        return '127.0.0.1' if $self->{type} eq 'local';
        die "SSH provider requires 'host'\n" unless $opts{host};
        return $opts{host};
    }
    sub delete_server {
        my ($self, $id, %opts) = @_;
        my $what = '' . ($id // $opts{host});
        push @events, [ delete => $self->{type}, $what ];
        die $delete_dies{$what} if defined $delete_dies{$what};
        return { stdout => '', stderr => '', exit => 0 };
    }
}

{
    package FakeKey;
    sub new            { bless {}, shift }
    sub path           { '/nonexistent/admin-key' }
    sub migration_hint { "hint\n" }
}

{
    package FakeList;
    sub new   { my ($c, @i) = @_; bless { items => [@i] }, $c }
    sub items { $_[0]{items} }
}

{
    # The cluster API: the OCPNodes and OCPNodeProviders it is given; the
    # OCPNode list dies with {dies} when that is set.
    package FakeK8s;
    sub new { my ($c, %a) = @_; bless {%a}, $c }
    sub k8s { $_[0] }
    sub object_to_struct { $_[1] }
    sub list {
        my ($self, $kind) = @_;
        push @events, [ 'api list', $kind ];
        die $self->{dies} if $kind eq 'OCPNode' && defined $self->{dies};
        return FakeList->new(@{ $self->{$kind} // [] });
    }
    sub patch { my ($self, $kind, $name) = @_; push @events, [ patch => $kind, $name ]; 1 }
}

my $HCP = "control_planes:\n  provider: hetzner\n  server_type: cx32\n  location: fsn1\n";

my $POLICE1 = "  - name: police1\n    provider: hetzner\n    providerId: \"111\"\n"
            . "    public_ip: 1.1.1.1\n";

sub project {
    my ($yaml, %a) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    $dir->child('.ocp')->mkpath;
    $dir->child('ocp.yaml')->spew_utf8("name: prod\n$yaml");
    $dir->child('.ocp', 'status.yaml')->spew_utf8(
        defined $a{status} ? "nodes:\n$a{status}" : "nodes: []\n");
    $dir->child('.ocp', 'deployed.yaml')->spew_utf8("registry: abc\n");
    $dir->child('kubeconfig.yaml')->spew_utf8("sops: encrypted\n");
    return OCP::Config->new(file => $dir->child('ocp.yaml')->stringify);
}

sub run_destroy {
    my ($config, %a) = @_;
    @events       = ();
    %labelled     = %{ $a{labelled}     // {} };
    %search_dies  = %{ $a{search_dies}  // {} };
    %delete_dies  = %{ $a{delete_dies}  // {} };
    %from_cr_dies = %{ $a{from_cr_dies} // {} };
    my $token = exists $a{token} ? $a{token} : 'tok';
    my $cmd = OCP::Cmd::Destroy->new(
        command_chain => [ FakeOcp->new(config => $config->file) ],
        k8s           => FakeK8s->new(
            dies            => $a{api_dies},
            OCPNode         => $a{ocpnodes} // [],
            OCPNodeProvider => $a{crs}      // [],
        ),
        force         => 1,
    );
    my ($out, $err) = ('', '');
    open my $ofh, '>', \$out or die;
    open my $efh, '>', \$err or die;
    my @ret = do {
        local *STDOUT = $ofh;
        local *STDERR = $efh;
        no warnings 'redefine';
        local *OCP::Provider::for_spec = sub {
            my ($class, $spec) = @_;
            return FakeProvider->new(type => $spec->{provider}, token => $token);
        };
        local *OCP::Provider::from_cr = sub {
            my ($class, $cr) = @_;
            my $name = $cr->{metadata}{name};
            die $from_cr_dies{$name} if defined $from_cr_dies{$name};
            return FakeProvider->new(type => 'hetzner', token => "tok-$name");
        };
        local *OCP::Secrets::hetzner_token = sub { $token };
        local *OCP::Cmd::Destroy::cluster_ssh_key =
              $a{real_key}         ? \&OCP::Cmd::Destroy::cluster_ssh_key
            : defined $a{key_dies} ? sub { push @events, [ 'ssh key' ]; die $a{key_dies} }
            :                        sub { push @events, [ 'ssh key' ]; FakeKey->new };
        eval { $cmd->execute([], []) };
    };
    return { out => $out, err => $err, ex => $@, ret => $ret[0], events => [@events] };
}

sub deleted { [ sort map { "$_->[1] $_->[2]" } grep { $_->[0] eq 'delete' } @{ $_[0]{events} } ] }

my $CLOSING = "\n[!!] Teardown INCOMPLETE: the lines above that say NOT torn down\n"
            . "     (or NOT deleted) name what is left standing.\n";

# A failure as Hetzner's adapter croaks it: with a location.
my $CROAKED = "Hetzner API error: unable to authenticate at /src/lib/OCP/Provider/Hetzner.pm line 421.\n";
my $WHY     = 'Hetzner API error: unable to authenticate';

my $LOCATION = qr/ at \S+ line \d+/;

# An API error as Kubernetes::REST throws it, a location on it.
sub api_error {
    my ($code, $reason, $message) = @_;
    return Kubernetes::REST::APIError->new(
        code      => $code,
        context   => 'GET /apis/ocp.io/v1/namespaces/ocp-system/ocpnodes',
        body      => encode_json({ kind => 'Status', reason => $reason, message => $message }),
        _location => " at /src/lib/OCP/Cmd/Destroy.pm line 441.\n",
    );
}

# ---------------------------------------------------------------- claim 1

subtest 'an ssh node with no host recorded: said on STDERR, named at the end, exit 1' => sub {
    # w1 as status.yaml records it, w2 as an OCPNode with neither a host nor
    # an address. Neither has anywhere for its uninstall to go.
    my $config = project($HCP, status => $POLICE1
        . "  - name: w1\n    provider: ssh\n    role: worker\n    public_ip: '-'\n");
    my @ocpnodes = ({ metadata => { name => 'w2' },
                      spec     => { providerRef => 'ssh-default', role => 'worker' },
                      status   => {} });
    my $r = run_destroy($config, ocpnodes => \@ocpnodes);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{out}, qr/^  - w1 \(ssh, -\)\n  - w2 \(ssh, -\)\n  - police1 \(hetzner, 1\.1\.1\.1\)\n/m,
        'the fixture: both listed, with no address';
    is $r->{err},
        "  Skipped: no host recorded, w1 keeps its RKE2/K3s install.\n"
      . "  Skipped: no host recorded, w2 keeps its RKE2/K3s install.\n"
      . "\n"
      . "[!!] Teardown INCOMPLETE: 2 machine(s) keep their RKE2/K3s install:\n"
      . "       - w1: no host recorded\n"
      . "       - w2: no host recorded\n"
      . "     Nothing is billed for them through OCP. Once they are\n"
      . "     reachable, run on each of them:\n"
      . "       rke2-uninstall.sh   # or k3s-uninstall.sh / k3s-agent-uninstall.sh\n",
        'on STDERR: each skip as it comes, and both in the closing list';
    unlike $r->{out}, qr/Skipped|no host/, 'nothing of it on STDOUT';
    unlike $r->{out}, qr/Cluster destroyed/, 'no success line';
    is $r->{ret}, 1, 'exit 1: two machines keep their install';
    is_deeply deleted($r), [ 'hetzner 111' ], 'police1 still deleted';
    ok !(grep { $_->[0] eq 'ssh key' } @{ $r->{events} }), 'no PIN2 asked: no ssh node has a host';
    ok !-f $config->status_file, 'the local state still goes, as for every uninstall left (k180)';
};

# ---------------------------------------------------------------- claim 2

subtest 'the old-label search fails: said, with its cause and the selector, exit 1' => sub {
    my $old = "[!!] The search under the old label ocp-cluster=hetzner-default failed: $WHY"
            . " -- a server of this cluster still labelled so is NOT deleted, and not named here.\n"
            . "     Look by hand:\n"
            . "       hcloud server list -l ocp-cluster=hetzner-default\n";

    # After a teardown: police1 recorded and deleted.
    my $config = project($HCP, status => $POLICE1);
    my $r = run_destroy($config, search_dies => { 'hetzner-default tok' => $CROAKED });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    ok scalar(grep { $_->[0] eq 'search' && $_->[1] eq 'hetzner-default' } @{ $r->{events} }),
        'the fixture: the old label was searched';
    is $r->{err}, "\n$old$CLOSING", 'on STDERR: the failed search, the cause as one line';
    unlike $r->{out}, qr/Cluster destroyed/, 'no success line';
    is $r->{ret}, 1, 'exit 1: what that search would name is unknown';
    is_deeply deleted($r), [ 'hetzner 111' ], 'police1 deleted all the same';

    # With nothing to delete: said before the question about the local state.
    $config = project($HCP);
    $r = run_destroy($config, search_dies => { 'hetzner-default tok' => $CROAKED });
    is $r->{err}, "\n$old$CLOSING", 'no nodes found: the same lines';
    like $r->{out}, qr/^No nodes to destroy\.$/m, 'the no-nodes path';
    is $r->{ret}, 1, 'exit 1 there too';

    # The control: a search that answers with nothing says nothing.
    $config = project($HCP, status => $POLICE1);
    $r = run_destroy($config);
    is $r->{err}, '', 'the control: nothing on STDERR';
    is $r->{ret}, 0, 'the control: exit 0';
};

# ---------------------------------------------------------------- claim 3

subtest 'one search answers, another fails: STDOUT says only what the answering one found' => sub {
    my @crs = ({ metadata => { name => 'hetzner-b' }, spec => { type => 'hetzner' } });
    my $config = project($HCP);
    my $r = run_destroy($config, crs => \@crs, search_dies => { 'prod tok-hetzner-b' => $CROAKED });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{out},
        qr/\Acontrol_planes\[1\]: a hetzner control plane is found by its ocp-cluster=prod label or not at all; no label search that answered found a server carrying it\.\n/,
        'on STDOUT: what the answering search found, and no more';
    unlike $r->{out}, qr/no server carries it|nothing to delete/,
        'not that no server carries it: one token was never searched';
    is $r->{err},
        "[!!] The label search for ocp-cluster=prod with OCPNodeProvider/hetzner-b's token failed:"
      . " $WHY -- a server only it would find is NOT torn down.\n"
      . "     Fix the cause and run `ocp destroy` again, or look by hand:\n"
      . "       hcloud server list -l ocp-cluster=prod\n" . $CLOSING,
        'on STDERR: the failed search, as before';

    # The control: every search answered.
    $r = run_destroy($config, crs => \@crs);
    like $r->{out},
        qr/\Acontrol_planes\[1\]: a hetzner control plane is found by its ocp-cluster=prod label or not at all; no server carries it, nothing to delete\.\n/,
        'the control: every search answered, so no server carries it';
};

# ---------------------------------------------------------------- claim 4

subtest 'why an OCPNodeProvider gave no adapter: one line, no location' => sub {
    my @crs = ({ metadata => { name => 'hetzner-b' }, spec => { type => 'hetzner' } });
    my @ocpnodes = ({ metadata => { name => 'w3' },
                      spec     => { providerRef => 'hetzner-b', role => 'worker' },
                      status   => { providerId => '333', publicIP => '3.3.3.3' } });
    my $refusal = sub {
        my ($why) = @_;
        return "[!!] Nothing was deleted: no Hetzner API token reaches these\n"
             . "     servers. They keep running and keep billing:\n"
             . "       - w3 (id 333, 3.3.3.3)\n"
             . "         no local Hetzner token, and OCPNodeProvider/hetzner-b gave none: $why\n";
    };

    # The Secret read through the API, answered 404.
    my $config = project($HCP);
    my $r = run_destroy($config, token => undef, crs => \@crs, ocpnodes => \@ocpnodes,
        from_cr_dies => { 'hetzner-b' => api_error(404, 'NotFound', 'secrets "hz-b" not found') });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err},
        qr/\A\Q${\ $refusal->('The cluster API answered (404 Not Found): secrets "hz-b" not found') }\E/,
        'an API error: the line naming what the API answered';
    unlike $r->{err}, $LOCATION, 'no Perl location';
    is $r->{ret}, 1, 'exit 1, nothing deleted';
    is_deeply deleted($r), [], 'nothing deleted';

    # A croak of the factory's own.
    $r = run_destroy($config, token => undef, crs => \@crs, ocpnodes => \@ocpnodes,
        from_cr_dies => { 'hetzner-b' => "from_cr: no token at /src/lib/OCP/Provider.pm line 146.\n" });
    like $r->{err}, qr/\A\Q${\ $refusal->('from_cr: no token') }\E/, 'a croak: its text, one line';
    unlike $r->{err}, $LOCATION, 'no Perl location';
};

subtest 'why the OCPNodes could not be read: one line, no location' => sub {
    my $unread = sub {
        my ($why) = @_;
        return "[!!] Could not read the OCPNodes from the cluster API:\n"
             . "     $why\n"
             . "     Workers come from .ocp/status.yaml, Hetzner labels and the\n"
             . "     hosts of ocp.yaml's ssh pools only; a worker only its OCPNode\n"
             . "     records -- a local pool's, or one added with `ocp node add` --\n"
             . "     may be missed and keep running.\n";
    };
    my $config = project($HCP, status => $POLICE1);

    my $r = run_destroy($config,
        api_dies => "Can't connect to 10.0.0.1:6443 (Connection refused) at /src/lib/OCP/K8s.pm line 12.\n");
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    is $r->{err}, $unread->("Can't connect to 10.0.0.1:6443 (Connection refused)"),
        'a croak: its text, one line';

    # A project of its own: the run above removed status.yaml.
    $config = project($HCP, status => $POLICE1);
    $r = run_destroy($config,
        api_dies => api_error(403, 'Forbidden', 'ocpnodes.ocp.io is forbidden: User "u" cannot list'));
    is $r->{err},
        $unread->('The cluster API denied the request (403 Forbidden): ocpnodes.ocp.io is forbidden: User "u" cannot list'),
        'an API error: the line naming what the API answered';
    unlike $r->{err}, $LOCATION, 'no Perl location';
    is_deeply deleted($r), [ 'hetzner 111' ], 'the teardown goes on';
};

subtest 'an uninstall that dies with a location: its lines, without it' => sub {
    my $config = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n");
    my $r = run_destroy($config, delete_dies => {
        'cp1.lan' => "cp1.lan: Uninstall of RKE2/K3s failed (exit 1): stopping rke2-server\n"
                   . "Failed to stop rke2-server.service: Connection refused"
                   . " at /usr/share/perl5/Rex/Interface/Exec/OpenSSH.pm line 88.\n" });
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err},
        qr/^  Warning: could not uninstall on cp1\.lan:\n    cp1\.lan: Uninstall of RKE2\/K3s failed \(exit 1\): stopping rke2-server\n    Failed to stop rke2-server\.service: Connection refused\nhint\n/m,
        'on STDERR: each line of the reason, as it came, the location gone';
    like $r->{err}, qr/^       - cp1\.lan: cp1\.lan: Uninstall of RKE2\/K3s failed \(exit 1\): stopping rke2-server$/m,
        'its first line in the closing list';
    unlike $r->{err}, $LOCATION, 'no Perl location anywhere';
    is $r->{ret}, 1, 'exit 1';
};

# ---------------------------------------------------------------- claim 5

subtest 'the SSH key refusal of several lines keeps its lines' => sub {
    # The real lookup, in dev mode (no keys.yaml) with no bootstrap key:
    # ClusterKey's refusal, two lines, the second lined up under ERROR:.
    my $config = project("control_planes:\n  provider: ssh\n  host: cp1.lan\n");
    my $key = $config->ssh_private_key_path;
    ok !-e $key, 'the fixture: no bootstrap key';
    my $r = run_destroy($config, real_key => 1);
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     SSH key '\Q$key\E' not found .* dev mode \(--nopassword\) uses it on every provider\.\n     Run 'ocp init' to create it\.\n     Their RKE2\/K3s uninstall will be SKIPPED\./m,
        'its two lines, under the block\'s indent, without ERROR:';
    unlike $r->{err}, qr/ERROR:/, 'no ERROR: label inside the [!!] block';

    # Lines of their own indent keep it: a recipient, a command to run.
    $r = run_destroy($config, key_dies =>
          "ERROR: This cluster's machines are reached with the admin key, whose private\n"
        . "half opens for the project key alone.\n"
        . "This run decrypts with SOPS_AGE_KEY_FILE (/x/age.key):\n"
        . "  age1qqqq\n"
        . "\n"
        . "That identity is not the project key. Register this machine as an operator:\n"
        . "  ocp keys operator add --name NAME --age age1qqqq\n");
    is $r->{ex}, '', 'ran without dying' or diag $r->{ex};
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     This cluster's machines are reached with the admin key, whose private\n     half opens for the project key alone\.\n     This run decrypts with SOPS_AGE_KEY_FILE \(\/x\/age\.key\):\n       age1qqqq\n     That identity is not the project key\. Register this machine as an operator:\n       ocp keys operator add --name NAME --age age1qqqq\n     Their RKE2\/K3s uninstall will be SKIPPED\./m,
        'each line kept, its own indent kept, the blank line gone';

    # One line stays one line, without its location (k353, t/353).
    $r = run_destroy($config, key_dies => "ssh.private_key: must be a string at /src/lib/OCP/Config.pm line 9.\n");
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     ssh\.private_key: must be a string\n     Their RKE2/m,
        'a one-line refusal: one line, no location';
};

# ============================================================== through run_cli

local $ENV{HETZNER_API_TOKEN} = 'hzTOKEN-k396-env-0123456789';

my $PIN1   = 'pin1-k396';
my $PIN2   = 'pin2-k396';
my $PROMPT = 'Enter PIN1 (cluster access): ';

local @ARGV = ();
my $ocp = OCP->new;

my $KUBECONFIG = join "\n",
    'apiVersion: v1', 'kind: Config', 'current-context: k396',
    'clusters:', '- name: k396', '  cluster:', '    server: https://127.0.0.1:9',
    '    insecure-skip-tls-verify: true',
    'users:', '- name: k396', '  user:', '    token: t',
    'contexts:', '- name: k396', '  context:', '    cluster: k396', '    user: k396', '';

# A secure-mode project as the machine that set it up has it: the project
# key in .ocp/ and behind PIN1 in age.key.enc, keys.yaml with the admin key
# behind PIN2, kubeconfig.yaml only with kubeconfig => 1. An ssh control
# plane, which the fallback lists: an ssh node, so destroy needs its key.
sub secure_origin {
    my (%o) = @_;
    my $dir = path(tempdir(CLEANUP => 1));
    my $s   = OCP::Secrets->new(project_dir => $dir, ocp => $ocp);
    $s->generate_age_key;
    $s->encrypt_age_key_with_password($PIN1);
    quietly(sub { OCP::Keys->new(project_dir => $dir)->add_cluster_keys(pin2 => $PIN2) });
    $s->save_kubeconfig($KUBECONFIG) if $o{kubeconfig};
    $ocp->dump_file($dir->child('ocp.yaml')->stringify, {
        name           => 'k396',
        control_planes => { provider => 'ssh', host => 'cp.k396.test' },
    });
    return $dir;
}

# $code with fd 1 and 2 on /dev/null: ssh-keygen, which add_cluster_keys
# runs, prints its randomart there.
sub quietly {
    my ($code) = @_;
    open my $out, '>&', \*STDOUT or die "dup: $!";
    open my $err, '>&', \*STDERR or die "dup: $!";
    open STDOUT, '>', '/dev/null' or die "null: $!";
    open STDERR, '>', '/dev/null' or die "null: $!";
    my @r = eval { $code->() };
    my $died = $@;
    open STDOUT, '>&', $out or die "restore: $!";
    open STDERR, '>&', $err or die "restore: $!";
    die $died if $died;
    return @r;
}

# What a clone gets: every committed file, no .ocp/.
sub clone_of {
    my ($src) = @_;
    my $dst = path(tempdir(CLEANUP => 1));
    $_->copy($dst->child($_->basename)) for grep { $_->is_file } $src->children;
    return $dst;
}

my $secure    = secure_origin();
my $secure_kc = secure_origin(kubeconfig => 1);

# An age identity no file of these projects is encrypted to.
my $foreign_id = path(tempdir(CLEANUP => 1))->child('foreign.key');
{
    my $other = path(tempdir(CLEANUP => 1));
    OCP::Secrets->new(project_dir => $other, ocp => $ocp)->generate_age_key;
    $foreign_id->spew($other->child('.ocp', 'age.key')->slurp);
}

our $LOG;

sub note_side {
    open my $fh, '>>', $LOG or die "log: $!";
    print {$fh} "@_\n";
    close $fh;
}

# Every Hetzner request recorded, and answered with no servers.
sub wire {
    my ($io, $req) = @_;
    (my $p = $req->url) =~ s{\Ahttps://api\.hetzner\.cloud/v1}{};
    ($p) = split /\?/, $p;
    note_side('REQUEST', $req->method, $p);
    return WWW::Hetzner::HTTPResponse->new(status => 200, content => encode_json({
        servers => [],
        meta    => { pagination => { page => 1, next_page => undef } },
    }));
}

# `ocp destroy --force @args` the way bin/ocp runs it -- OCP->run_cli -- in a
# child: in $dir, $stdin as STDIN (a file: no terminal), the wire fake, the
# terminal reads counted, SOPS_AGE_KEY_FILE as given.
sub run_cli_destroy {
    my ($dir, $stdin, %o) = @_;
    my ($in, $out, $err, $log) = map { Path::Tiny->tempfile } 1 .. 4;
    $in->spew($stdin);

    my $pid = fork // die "fork: $!";
    unless ($pid) {
        local $LOG = "$log";
        chdir $dir or die "chdir: $!";
        local $ENV{HOME} = $dir->stringify;
        local $ENV{SOPS_AGE_KEY_FILE} = $o{sops_age_key_file} if defined $o{sops_age_key_file};
        open STDIN,  '<', "$in"  or die;
        open STDOUT, '>', "$out" or die;
        open STDERR, '>', "$err" or die;
        alarm 120;
        no warnings 'redefine';
        *WWW::Hetzner::LWPIO::call = \&wire;
        *OCP::Password::ReadMode   = sub { note_side('TERMINAL', 'ReadMode'); return };
        *OCP::Password::ReadLine   = sub { note_side('TERMINAL', 'ReadLine'); return };
        # Never an SSH connection: every run here stops or skips before one.
        *OCP::Provider::SSH::run_command = sub { note_side('SSH', $_[1]); die "no SSH here\n" };
        @ARGV = ('destroy', '--force', @{ $o{args} // [] });
        my $code = OCP->run_cli;
        close STDOUT;
        close STDERR;
        POSIX::_exit($code);
    }
    waitpid $pid, 0;
    my $st = $?;
    my @side = -s $log ? $log->lines_utf8({ chomp => 1 }) : ();
    return {
        signal   => $st & 127,
        exit     => $st >> 8,
        out      => $out->slurp_utf8,
        err      => $err->slurp_utf8,
        requests => [ grep { /\AREQUEST / }  @side ],
        terminal => [ grep { /\ATERMINAL / } @side ],
        ssh      => [ grep { /\ASSH / }      @side ],
    };
}

# A refusal of the project key: the dispatcher's line for a user error, and
# destroy stopped there -- nothing deleted, nothing skipped, nothing said
# about the uninstalls.
sub stopped_at_key_ok {
    my ($what, $r, $re) = @_;
    is $r->{signal}, 0, "$what: no signal (alarm)";
    isnt $r->{exit}, 0, "$what: exit non-zero";
    like $r->{err}, $re, "$what: OCP::Secrets' refusal, as the dispatcher prints it";
    unlike $r->{err}, qr/internal error/, "$what: not called an internal error";
    unlike $r->{err}, qr/Could not obtain the SSH key|SKIPPED|Skipped/,
        "$what: not taken for a key that cannot be had";
    unlike $r->{out}, qr/^Deleting /m, "$what: nothing deleted or uninstalled";
    ok -f $r->{dir}->child('ocp.yaml'), "$what: the project is as it was";
    is_deeply $r->{ssh}, [], "$what: no SSH";
}

# The lookup failed, and the run went on without the key, as it always did.
sub downgraded_ok {
    my ($what, $r) = @_;
    is $r->{signal}, 0, "$what: no signal (alarm)";
    unlike $r->{err}, qr/^Error:/m, "$what: no refusal";
    like $r->{out}, qr/^Deleting cp\.k396\.test\.\.\.$/m, "$what: the teardown went on";
    like $r->{err}, qr/^  Skipped: no SSH key, cp\.k396\.test keeps its RKE2\/K3s install\.$/m,
        "$what: the uninstall skipped, and said";
    is $r->{exit}, 1, "$what: exit 1, the machine keeps its install";
    is_deeply $r->{ssh}, [], "$what: no SSH";
}

# ---------------------------------------------------------------- claim 6

subtest 'a wrong PIN1 for the SSH key: said, and destroy stops before anything is deleted' => sub {
    my $clone = clone_of($secure);
    ok !-e $clone->child('kubeconfig.yaml'), 'the fixture: no kubeconfig.yaml, so no PIN1 before';
    my $r = run_cli_destroy($clone, "not-the-pin\n", args => [ '--pins-stdin' ]);
    $r->{dir} = $clone;
    (my $refusal = OCP::Secrets->_wrong_pin1_refusal) =~ s/\s+\z//;
    is $r->{err}, "$PROMPT\nError: $refusal\n",
        'STDERR: the PIN1 prompt, then the refusal, unchanged -- and nothing else';
    stopped_at_key_ok('wrong PIN1', $r, qr/^Error: PIN1 does not open age\.key\.enc\./m);
    like $r->{out}, qr/^  - cp\.k396\.test \(ssh, cp\.k396\.test\)$/m,
        'listed before the question, as every teardown is';
    ok !-e $clone->child('.ocp/age.key'), 'no key written';
};

subtest 'a broken SOPS_AGE_KEY_FILE for the SSH key: said, and destroy stops' => sub {
    my $clone = clone_of($secure);
    my $r = run_cli_destroy($clone, '', sops_age_key_file => '/nonexistent/k396.key');
    $r->{dir} = $clone;
    stopped_at_key_ok('no such file', $r,
        qr/^Error: SOPS_AGE_KEY_FILE is set to \/nonexistent\/k396\.key, and there is no such file\.$/m);

    $r = run_cli_destroy($clone, '', sops_age_key_file => "$foreign_id");
    $r->{dir} = $clone;
    stopped_at_key_ok('a key the project is not bound to', $r,
        qr/^Error: This age key does not belong to this project\.$/m);
};

subtest 'the right PIN1 and a wrong PIN2: the downgrade it always was' => sub {
    my $clone = clone_of($secure);
    my $r = run_cli_destroy($clone, "$PIN1\nnot-the-pin2\n", args => [ '--pins-stdin' ]);
    my @asked = $r->{err} =~ /(Enter PIN\d)/g;
    is_deeply \@asked, [ 'Enter PIN1', 'Enter PIN2' ], 'PIN1 asked once, then PIN2, in that order';
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     Wrong PIN2 or no admin-key found!\n     Their RKE2\/K3s uninstall will be SKIPPED\./m,
        'the wrong PIN2 said in the block';
    downgraded_ok('wrong PIN2', $r);
    ok -f $clone->child('.ocp/age.key'), 'the right PIN1 cached the key, as every command does';
};

subtest 'nobody to ask: no PIN1 asked, the downgrade it always was, in lines' => sub {
    my $clone = clone_of($secure);
    my $r = run_cli_destroy($clone, '');
    unlike $r->{err}, qr/Enter PIN/, 'no PIN asked';
    is_deeply $r->{terminal}, [], 'the terminal is never touched';
    like $r->{err},
        qr/^\[!!\] Could not obtain the SSH key for the ssh-provider nodes:\n     This cluster's machines trust the admin key \(secure mode, provider 'ssh'\),\n     which is behind PIN2 .* and there is no terminal to ask on\.\n     Re-run ocp destroy from an interactive shell\.\n     Their RKE2\/K3s uninstall will be SKIPPED\./m,
        'ClusterKey\'s refusal, its three lines under the block\'s indent';
    downgraded_ok('no terminal', $r);
    ok !-e $clone->child('.ocp/age.key'), 'no key unlocked';
};

# ---------------------------------------------------------------- claim 7

subtest 'a broken SOPS_AGE_KEY_FILE with HETZNER_API_TOKEN set: destroy stops before it lists' => sub {
    for my $case ([ 'no such file', '/nonexistent/k396.key',
                    qr/^Error: SOPS_AGE_KEY_FILE is set to \/nonexistent\/k396\.key, and there is no such file\.$/m ],
                  [ 'a key the project is not bound to', "$foreign_id",
                    qr/^Error: This age key does not belong to this project\.$/m ]) {
        my ($what, $file, $re) = @$case;
        my $clone = clone_of($secure_kc);
        ok -f $clone->child('kubeconfig.yaml'), "$what -- the fixture: kubeconfig.yaml";
        my $r = run_cli_destroy($clone, '', sops_age_key_file => $file);
        is $r->{signal}, 0, "$what: no signal (alarm)";
        isnt $r->{exit}, 0, "$what: exit non-zero";
        like $r->{err}, $re, "$what: OCP::Secrets' refusal, as the dispatcher prints it";
        unlike $r->{err}, qr/OCPNodes|cluster API|NOT torn down/,
            "$what: not taken for an API that does not answer";
        is $r->{out}, '', "$what: nothing on STDOUT -- nothing listed";
        is_deeply $r->{requests}, [], "$what: no label search";
        ok -f $clone->child('kubeconfig.yaml'), "$what: kubeconfig.yaml kept";
    }
};

done_testing;
