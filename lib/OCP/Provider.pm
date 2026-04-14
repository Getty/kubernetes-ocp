package OCP::Provider;
# ABSTRACT: Provider factory for infrastructure backends

use strict;
use warnings;

our $VERSION = '0.001';

sub for_spec {
    my ($class, $spec, %opts) = @_;
    my $type = $spec->{provider} // 'hetzner';

    if ($type eq 'hetzner') {
        require OCP::Provider::Hetzner;
        return OCP::Provider::Hetzner->new(
            token        => $opts{token},
            cluster_name => $opts{cluster_name},
        );
    } elsif ($type eq 'ssh') {
        require OCP::Provider::SSH;
        return OCP::Provider::SSH->new(
            ssh_key_path => $opts{ssh_key_path},
        );
    } elsif ($type eq 'local') {
        require OCP::Provider::Local;
        return OCP::Provider::Local->new(
            verbose => $opts{verbose} // 0,
        );
    } else {
        die "Unsupported provider: $type\n";
    }
}

1;

__END__

=head1 NAME

OCP::Provider - Factory for infrastructure provider backends

=head1 SYNOPSIS

    use OCP::Provider;

    my $provider = OCP::Provider->for_spec($cp_spec,
        token        => $hetzner_token,
        cluster_name => $config->name,
        ssh_key_path => $ssh_key_path,
    );

    $provider->upload_ssh_key($key_name, $pubkey);
    my $server = $provider->create_server(%opts);
    $provider->cleanup_on_failure($server->{id});

=head1 DESCRIPTION

Factory that returns the appropriate provider based on the control plane spec.

=cut
