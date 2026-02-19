package OCP::Cmd::Edit;
# ABSTRACT: Edit OCP config via TUI

use Moo;
use MooX::Cmd;
use MooX::Options;
use Path::Tiny qw(path);

use OCP;
use OCP::Config;
use OCP::Secrets;

with 'OCP::Role::Cmd';

our $VERSION = '0.1.0';

sub execute {
    my ($self, $args, $chain) = @_;

    my $config_file = $self->ocp->config;
    die "No $config_file found. Run 'ocp init' first.\n" unless -f $config_file;

    my $config = OCP::Config->new(file => $config_file);
    my $spec = $config->spec;
    my $cps = $config->control_planes;  # ArrayRef
    my $k8s = $config->kubernetes;
    my $secrets = OCP::Secrets->new(project_dir => $config->project_dir);

    require OCP::UI;

    # Page 1: Basics
    my $basics = OCP::UI->new(
        title  => 'OCP Edit',
        fields => [
            { name => 'name', type => 'text', label => 'Cluster Name',
              default => $spec->{name} // 'mycluster' },
            { name => 'dist', type => 'choice', label => 'Distribution',
              options => [
                  { label => 'RKE2 (recommended)', value => 'rke2' },
                  { label => 'K3s (lightweight)',   value => 'k3s' },
              ], default => $k8s->{dist} // 'rke2' },
        ],
    )->run;
    return unless $basics;

    # CP loop: show existing CPs, allow editing each + adding new ones
    my @new_cps;
    my $hetzner_token;
    my $hz;

    my @base_ctx = (
        { label => 'Cluster Name', value => $basics->{name} },
        { label => 'Distribution', value => $basics->{dist} },
    );

    # Re-add existing CPs (user can modify or skip)
    for my $i (0 .. $#$cps) {
        my $existing = $cps->[$i];
        my $cp = eval {
            $self->_edit_cp($secrets, \$hetzner_token, \$hz, $i, $existing, \@base_ctx)
        };
        if ($@) {
            print "\nError: $@\n";
            return;
        }
        last unless $cp;  # Cancel
        if (ref $cp eq 'ARRAY') {
            push @new_cps, @$cp;
        } else {
            push @new_cps, $cp;
        }
    }

    return unless @new_cps;

    # Add more?
    while (1) {
        my $more = OCP::UI->new(
            title   => sprintf('OCP Edit - %d CP(s)', scalar @new_cps),
            context => \@base_ctx,
            fields  => [
                { name => 'add_more', type => 'choice', label => 'Add another CP?',
                  options => [
                      { label => 'No, done',  value => 'no' },
                      { label => 'Yes, add',  value => 'yes' },
                  ], default => 'no' },
            ],
        )->run;
        last unless $more && $more->{add_more} eq 'yes';

        my $cp = eval {
            $self->_edit_cp($secrets, \$hetzner_token, \$hz, scalar @new_cps, undef, \@base_ctx)
        };
        if ($@) {
            print "\nError: $@\n";
            return;
        }
        last unless $cp;
        if (ref $cp eq 'ARRAY') {
            push @new_cps, @$cp;
        } else {
            push @new_cps, $cp;
        }
    }

    # Save token if entered manually
    if ($hetzner_token && !$secrets->hetzner_token) {
        $secrets->set_hetzner_token($hetzner_token);
        print "[ok] Hetzner token saved (encrypted)\n";
    }

    OCP::Config->write_spec($config_file,
        name => $basics->{name},
        dist => $basics->{dist},
        cps  => \@new_cps,
    );
    print "Config updated.\n";
}

sub _edit_cp {
    my ($self, $secrets, $token_ref, $hz_ref, $cp_num, $existing, $base_ctx) = @_;

    require OCP::UI;
    my @ctx = @{$base_ctx // []};
    my $default_provider = $existing ? $existing->{provider} : 'hetzner';

    # Provider Auswahl
    my $prov = OCP::UI->new(
        title   => sprintf('OCP Edit - Control Plane %d', $cp_num + 1),
        context => \@ctx,
        fields  => [
            { name => 'provider', type => 'choice', label => 'CP Provider',
              options => [
                  { label => 'Hetzner Cloud', value => 'hetzner' },
                  { label => 'SSH (existing)', value => 'ssh' },
                  { label => 'Local',          value => 'local' },
              ], default => $default_provider },
        ],
    )->run;
    return undef unless $prov;

    my $provider = $prov->{provider};
    my @cp_ctx = (@ctx, { label => 'CP Provider', value => $provider });

    if ($provider eq 'hetzner') {
        $$token_ref //= $secrets->hetzner_token;
        unless ($$token_ref) {
            my $tok = OCP::UI->new(
                title   => 'OCP Edit - Hetzner Token',
                context => \@cp_ctx,
                fields  => [
                    { name => 'token', type => 'text', label => 'API Token' },
                ],
            )->run;
            return undef unless $tok;
            $$token_ref = $tok->{token};
            die "No Hetzner API token provided.\n" unless $$token_ref;
        }

        unless ($$hz_ref) {
            print "Testing Hetzner API connection... ";
            require OCP::Hetzner;
            $$hz_ref = OCP::Hetzner->new(token => $$token_ref);
            $$hz_ref->location_options;
            print "OK\n\n";
        }

        my $details = OCP::UI->new(
            title   => sprintf('OCP Edit - Hetzner CP %d+', $cp_num + 1),
            context => \@cp_ctx,
            fields  => [
                { name => 'count', type => 'choice', label => 'How many?',
                  options => [
                      { label => '1 (single)',  value => '1' },
                      { label => '3 (HA)',      value => '3' },
                  ], default => '1' },
                { name => 'location', type => 'choice', label => 'Location',
                  options => $$hz_ref->location_options,
                  default => ($existing ? $existing->{location} : 'fsn1') },
                { name => 'server_type', type => 'choice', label => 'Server Type',
                  options => $$hz_ref->server_type_options,
                  default => ($existing ? $existing->{serverType} : 'cpx21') },
            ],
        )->run;
        return undef unless $details;

        my $cp = {
            provider   => 'hetzner',
            serverType => $details->{server_type},
            location   => $details->{location},
            image      => ($existing ? $existing->{image} : 'debian-13'),
        };
        my $count = $details->{count} // 1;
        return [($cp) x $count];
    }
    elsif ($provider eq 'ssh') {
        my $ssh = OCP::UI->new(
            title   => sprintf('OCP Edit - SSH CP %d', $cp_num + 1),
            context => \@cp_ctx,
            fields  => [
                { name => 'host', type => 'text', label => 'SSH Host',
                  default => ($existing ? $existing->{host} : '') },
            ],
        )->run;
        return undef unless $ssh;
        return { provider => 'ssh', host => $ssh->{host} };
    }
    elsif ($provider eq 'local') {
        return { provider => 'local' };
    }

    return undef;
}

1;
