package OCP::Cmd::BrowserCert;
# ABSTRACT: Extract client certificate from kubeconfig for browser import

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);
use MIME::Base64 qw(decode_base64);
use File::Temp qw(tempdir);
use YAML::XS ();

use OCP;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

option output => (
    is      => 'ro',
    format  => 's',
    short   => 'o',
    doc     => 'Output .p12 filename',
    default => sub { 'ocp-browser.p12' },
);

option save_ca => (
    is    => 'ro',
    doc   => 'Also save CA cert as separate .crt file',
);

sub execute {
    my ($self, $args, $chain) = @_;

    my $file = $self->ocp->config;
    unless (-f $file) {
        die "Config file '$file' not found.\n";
    }

    my $config  = OCP::Config->new(file => $file);
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    # Ensure age key is available (may prompt for PIN1)
    $secrets->ensure_age_key;

    # Decrypt kubeconfig
    my $kubeconfig_yaml = $secrets->read_kubeconfig;
    unless ($kubeconfig_yaml) {
        die "Cannot decrypt kubeconfig. Make sure kubeconfig.yaml exists.\n";
    }

    my $kubeconfig = YAML::XS::Load($kubeconfig_yaml);

    # Extract client cert + key from first user
    my $user = $kubeconfig->{users}[0]{user}
        or die "No user found in kubeconfig.\n";

    my $cert_b64 = $user->{'client-certificate-data'}
        or die "No client-certificate-data in kubeconfig.\n";
    my $key_b64 = $user->{'client-key-data'}
        or die "No client-key-data in kubeconfig.\n";

    my $cert_pem = decode_base64($cert_b64);
    my $key_pem  = decode_base64($key_b64);

    # Extract CA cert
    my $cluster = $kubeconfig->{clusters}[0]{cluster}
        or die "No cluster found in kubeconfig.\n";
    my $ca_b64 = $cluster->{'certificate-authority-data'};
    my $ca_pem = $ca_b64 ? decode_base64($ca_b64) : undef;

    # Show cert info
    my $tmpdir = tempdir(CLEANUP => 1);
    my $cert_file = "$tmpdir/client.crt";
    my $key_file  = "$tmpdir/client.key";
    my $ca_file   = "$tmpdir/ca.crt";

    path($cert_file)->spew_raw($cert_pem);
    path($key_file)->spew_raw($key_pem);
    path($ca_file)->spew_raw($ca_pem) if $ca_pem;

    print "Client certificate:\n";
    system("openssl x509 -in '$cert_file' -noout -subject -issuer -dates 2>/dev/null");
    print "\n";

    # Build PKCS12
    my $output = $self->output;
    my $cluster_name = $config->name // 'ocp';

    my @cmd = (
        'openssl', 'pkcs12', '-export',
        '-out',    $output,
        '-inkey',  $key_file,
        '-in',     $cert_file,
        '-name',   "$cluster_name client cert",
    );
    push @cmd, '-certfile', $ca_file if $ca_pem;

    print "Creating $output ...\n";
    print "(Set a password to protect the .p12, or press Enter for empty)\n\n";

    system(@cmd);
    if ($? != 0) {
        die "Failed to create PKCS12 file.\n";
    }

    print "\nBrowser cert: $output\n";

    # Optionally save CA cert
    if ($self->save_ca && $ca_pem) {
        my $ca_output = $output;
        $ca_output =~ s/\.p12$/-ca.crt/;
        path($ca_output)->spew_raw($ca_pem);
        print "CA cert:      $ca_output\n";
        print "\nFor K8s Gateway mTLS:\n";
        print "  kubectl -n hi create secret generic client-ca --from-file=ca.crt=$ca_output\n";
    }

    print "\nImport into browser:\n";
    print "  Chrome:  Settings > Privacy > Security > Manage certificates > Import\n";
    print "  Firefox: Settings > Privacy > View Certificates > Your Certificates > Import\n";
    print "  Safari:  Double-click .p12 > Keychain Access imports it\n";

    return 0;
}

1;
