package OCP::Node;
# ABSTRACT: Trigger-neutral node reconcile state machine

use Moo;
use namespace::clean;

our $VERSION = '0.001';

has cr            => (is => 'ro', required => 1);
has k8s           => (is => 'ro', required => 1);
has provider      => (is => 'ro');
has ssh_key       => (is => 'ro');
has server_url    => (is => 'ro');
has join_token    => (is => 'ro');
has distribution  => (is => 'ro', default => sub { 'rke2' });
has registry_cfg  => (is => 'ro');
has verbose       => (is => 'ro', default => 0);
has reconciler_id => (is => 'ro', default => sub { 'cli' });

sub name  { $_[0]->cr->{metadata}{name} }
sub role  { $_[0]->cr->{spec}{role} }
sub phase { $_[0]->cr->{status}{phase} // 'Pending' }

sub from_cr {
    my ($class, $cr, %deps) = @_;
    return $class->new(cr => $cr, %deps);
}

1;
