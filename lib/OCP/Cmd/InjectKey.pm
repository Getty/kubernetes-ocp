package OCP::Cmd::InjectKey;
# ABSTRACT: Hand the robo SSH key to the running robocop (security_level inject)

use Moo;
use MooX::Cmd;
use MooX::Options;

use File::Temp ();
use IO::Async::Loop;
use Net::Async::Kubernetes;

use OCP::Config;
use OCP::Keys;
use OCP::Robocop::KeyInjection;
use OCP::Secrets;

with 'OCP::Role::Cmd';

#
# The CLI half of robocop.security_level `inject` (k2). The private robo key
# is never stored in the cluster: this command decrypts it (PIN1 for the age
# layer, PIN2 as the admin approval), opens a Kubernetes port-forward to every
# running robocop pod and hands it over (OCP::Robocop::KeyInjection). robocop
# keeps it in memory only, so after a pod restart this is run again -- the
# OCPNodes waiting for it say so (SSHKeyAvailable=False).
#
# Output: progress and the acknowledged fingerprint on STDOUT; every failure,
# with what to do about it, on STDERR. The key itself is never printed.
#

my $NAMESPACE = 'ocp-system';

option timeout => (
    is      => 'ro',
    format  => 'i',
    default => 30,
    doc     => 'Seconds to wait for robocop to answer (default: 30)',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    die "Config file '$file' not found. Run 'ocp init' first.\n" unless -f $file;

    my $config = OCP::Config->new(file => $file);

    my $level = $config->robocop_security_level;
    die "ERROR: robocop.security_level is '$level', not 'inject'.\n"
      . "       robocop reads its key from the robocop-credentials Secret;\n"
      . "       there is nothing to inject. For in-memory delivery set\n"
      . "       robocop.security_level: inject and run 'ocp deploy-robocop'.\n"
        unless $level eq 'inject';

    my $keys = OCP::Keys->new(project_dir => $config->project_dir);
    die "ERROR: No keys.yaml in this project, so there is no robo key to inject.\n"
      . "       Dev mode (ocp init --nopassword) has none; inject needs a\n"
      . "       secure-mode project.\n"
        unless $keys->has_keys_file;

    # PIN1: the age layer every key and the kubeconfig are encrypted with.
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);
    $secrets->ensure_age_key;

    # PIN2: the robo key alone needs only PIN1, but putting it into a running
    # controller is an admin act, gated like secret_approved's Secret write.
    $self->require_admin_approval($config, 'Injecting the robo key into robocop');

    my $robo = $keys->get_automation_key
        or die "ERROR: No automation (robo) key found in keys.yaml.\n";

    # Refuse locally what robocop would refuse anyway, before touching the cluster.
    my $fp = eval {
        OCP::Robocop::KeyInjection->validate_key($robo->{private}, $robo->{public});
    };
    die "ERROR: The robo key in keys.yaml cannot be injected: $@" unless $fp;

    my $kube = $self->_async_kube($secrets);
    my @pods = $self->_robocop_pods($kube);
    die "ERROR: No running robocop pod in $NAMESPACE.\n"
      . "       Run 'ocp deploy-robocop' and wait for the pod to start\n"
      . "       (it stays not Ready until it holds a key -- that is expected).\n"
        unless @pods;

    print "Injecting robo key $fp into robocop...\n";

    my $failed = 0;
    for my $pod (@pods) {
        my $got = eval {
            OCP::Robocop::KeyInjection->send_key(
                kube      => $kube,
                pod       => $pod,
                namespace => $NAMESPACE,
                key       => $robo->{private},
                timeout   => $self->timeout,
            )->get;
        };
        if (defined $got) {
            print "  [ok] $pod: key accepted ($got), held in memory\n";
            next;
        }
        $failed++;
        my $err = $@ || "unknown error\n";
        print STDERR "ERROR: $pod: $err";
    }

    return $failed ? 1 : 0;
}

# Net::Async::Kubernetes on the project's kubeconfig. It takes a path, so the
# decrypted kubeconfig goes to a temp file that lives as long as the command
# (the same way OCP::Cmd::DeployRobocop reaches the cluster).
sub _async_kube {
    my ($self, $secrets) = @_;

    my $kc = $secrets->read_kubeconfig;
    die "ERROR: Cannot decrypt kubeconfig.yaml. Make sure .ocp/age.key exists.\n"
        unless $kc;

    my $fh = File::Temp->new(SUFFIX => '.yaml', UNLINK => 1);
    print {$fh} $kc;
    close $fh;
    $self->{_kubeconfig_tmp} = $fh;

    my $loop = IO::Async::Loop->new;
    my $kube = Net::Async::Kubernetes->new(kubeconfig => $fh->filename);
    $loop->add($kube);
    return $kube;
}

# Names of the robocop pods that can take a key: Running and not on their way
# out. Filtered here on the app=robocop label rather than by selector, so the
# answer does not depend on how the client passes query parameters.
sub _robocop_pods {
    my ($self, $kube) = @_;

    my $list = $kube->list('Pod', namespace => $NAMESPACE)->get;
    my @names;
    for my $pod (@{ $list->items // [] }) {
        my $meta = $pod->metadata or next;
        next unless (($meta->labels // {})->{app} // '') eq 'robocop';
        next if $meta->deletionTimestamp;
        next unless $pod->status && ($pod->status->phase // '') eq 'Running';
        push @names, $meta->name;
    }
    return sort @names;
}

1;

__END__

=head1 NAME

OCP::Cmd::InjectKey - Hand the robo SSH key to the running robocop (security_level inject)

=head1 SYNOPSIS

    ocp inject-key                # PIN1 (if age.key is locked) + PIN2
    ocp inject-key --timeout 60

=head1 DESCRIPTION

For C<robocop.security_level: inject>. Decrypts the robo (automation) key from
F<keys.yaml>, asks for PIN2 as the admin approval, and sends the private key
through a Kubernetes port-forward to every running robocop pod in
C<ocp-system> (protocol: L<OCP::Robocop::KeyInjection>). robocop checks it
against the public half it was deployed with and holds it in memory only --
it is never written to a Secret or to disk.

A pod restart loses the key. robocop then shows it: the pod is not Ready, and
OCPNodes that need SSH carry C<SSHKeyAvailable=False>. Run this command again.

Refused, with the reason on STDERR, when the level is not C<inject>, in dev
mode (no F<keys.yaml>), on a wrong PIN2, and when no robocop pod is running.
Exits 1 if any pod did not accept the key.

=head1 OPTIONS

=over 4

=item B<--timeout> I<seconds>

How long to wait for robocop's answer per pod (default 30).

=back

=head1 SEE ALSO

L<OCP::Robocop::KeyInjection>, L<OCP::Robocop::Controller>,
L<OCP::Cmd::DeployRobocop>

=cut
