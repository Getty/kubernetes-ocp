package OCP::ReadonlyKubeconfig;
# ABSTRACT: A read-only ServiceAccount and the kubeconfig that carries its token

use strict;
use warnings;
use Carp qw( croak );
use MIME::Base64 qw( decode_base64 );
use Scalar::Util qw( blessed );

use OCP;
use OCP::Cmd::Apply::K8s;
use OCP::Kubeconfig;

# Everything lives in this namespace, next to robocop.
sub namespace { 'ocp-system' }

# The shared ClusterRole adding what the built-in `view` leaves out.
sub role_name { 'ocp-readonly' }

sub default_name { 'leitstand' }

sub sa_name     { 'ocp-readonly-'.$_[1] }
sub secret_name { 'ocp-readonly-'.$_[1].'-token' }

# "ocp-readonly-" (13) + NAME + "-token" (6) has to stay a DNS label (63).
sub validate_name {
  my ( $self, $name ) = @_;

  return "--name needs a value.\n" unless defined $name && length $name;
  return "Invalid --name '".$name."': use 1 to 32 lower-case letters, digits or '-', "
    ."starting and ending with a letter or digit (it becomes part of the "
    ."ServiceAccount name 'ocp-readonly-NAME').\n"
    unless $name =~ /\A[a-z0-9](?:[-a-z0-9]{0,30}[a-z0-9])?\z/;
  return;
}

sub resources {
  my ( $self, $name ) = @_;

  my $ns  = $self->namespace;
  my $sa  = $self->sa_name($name);
  my $rbac = 'rbac.authorization.k8s.io/v1';
  my $subject = [ { kind => 'ServiceAccount', name => $sa, namespace => $ns } ];

  return (
    {
      apiVersion => 'v1',
      kind       => 'ServiceAccount',
      metadata   => { name => $sa, namespace => $ns },
    },
    {
      apiVersion => $rbac,
      kind       => 'ClusterRole',
      metadata   => { name => $self->role_name },
      rules      => [
        { apiGroups => [''], resources => ['nodes'], verbs => [qw( get list watch )] },
        {
          apiGroups => ['ocp.internal'],
          resources => [qw( ocpnodes ocpnodeproviders )],
          verbs     => [qw( get list watch )],
        },
      ],
    },
    {
      apiVersion => $rbac,
      kind       => 'ClusterRoleBinding',
      metadata   => { name => $sa.'-view' },
      roleRef    => { apiGroup => 'rbac.authorization.k8s.io', kind => 'ClusterRole', name => 'view' },
      subjects   => $subject,
    },
    {
      apiVersion => $rbac,
      kind       => 'ClusterRoleBinding',
      metadata   => { name => $sa },
      roleRef    => { apiGroup => 'rbac.authorization.k8s.io', kind => 'ClusterRole', name => $self->role_name },
      subjects   => $subject,
    },
    {
      apiVersion => 'v1',
      kind       => 'Secret',
      type       => 'kubernetes.io/service-account-token',
      metadata   => {
        name        => $self->secret_name($name),
        namespace   => $ns,
        annotations => { 'kubernetes.io/service-account.name' => $sa },
      },
    },
  );
}

# Server-Side Apply of everything, then wait for the token controller to fill
# the Secret. Applying again changes nothing and returns the same token.
# Returns the token.
sub ensure {
  my ( $self, $api, $name, %opt ) = @_;

  OCP::Cmd::Apply::K8s::server_side_apply( $self, $api, $_ ) for $self->resources($name);

  my $timeout  = $opt{timeout}  // 30;
  my $interval = $opt{interval} // 1;
  my $waited   = 0;

  while (1) {
    my $token = $self->_token( $api, $name );
    return $token if defined $token && length $token;
    last if $waited >= $timeout;
    sleep $interval;
    $waited += $interval;
  }

  croak 'Timed out after '.$timeout.'s: the token controller has not filled Secret '
    .$self->namespace.'/'.$self->secret_name($name).". Is kube-controller-manager running?\n";
}

sub _token {
  my ( $self, $api, $name ) = @_;

  my $secret = eval {
    $api->get( 'Secret', name => $self->secret_name($name), namespace => $self->namespace );
  };
  return unless $secret;
  $secret = $api->k8s->object_to_struct($secret) if blessed $secret;
  my $b64 = ( $secret->{data} // {} )->{token};
  return unless defined $b64 && length $b64;
  return decode_base64($b64);
}

# Removes the access. The ClusterRole `ocp-readonly` is shared by all names and
# grants nothing without a binding, so it always stays. Missing objects are
# fine: running it twice is the same as running it once.
# Returns the list of "Kind/name" actually deleted.
sub revoke {
  my ( $self, $api, $name ) = @_;

  my $sa = $self->sa_name($name);
  my $ns = $self->namespace;
  my @targets = (
    [ Secret             => $self->secret_name($name), $ns ],
    [ ClusterRoleBinding => $sa.'-view' ],
    [ ClusterRoleBinding => $sa ],
    [ ServiceAccount     => $sa, $ns ],
  );

  my @deleted;
  for my $t (@targets) {
    my ( $kind, $n, $namespace ) = @$t;
    if ( eval { $api->delete( $kind, name => $n, ( $namespace ? ( namespace => $namespace ) : () ) ); 1 } ) {
      push @deleted, $kind.'/'.$n;
      next;
    }
    my $err = $@;
    next if $err =~ /\b404\b|not found/i;
    croak 'Cannot delete '.$kind.'/'.$n.': '.$err;
  }
  return @deleted;
}

# A kubeconfig for the token. Server and CA come from the admin kubeconfig;
# no admin credential is copied.
sub kubeconfig {
  my ( $self, %arg ) = @_;

  my $admin = OCP::Kubeconfig->parse( $arg{admin_kubeconfig} );
  my $src   = ( $admin->{clusters} || [] )->[0]
    or croak "The admin kubeconfig has no cluster entry.\n";
  my $cluster = $src->{cluster} || {};

  my $user    = $self->sa_name( $arg{name} );
  my $cname   = $arg{cluster_name};
  my %keep    = map { $_ => $cluster->{$_} } grep { defined $cluster->{$_} }
    qw( server certificate-authority-data certificate-authority insecure-skip-tls-verify tls-server-name );

  return OCP->dump( {
    apiVersion => 'v1',
    kind       => 'Config',
    clusters   => [ { name => $cname, cluster => \%keep } ],
    users      => [ { name => $user, user => { token => $arg{token} } } ],
    contexts   => [ { name => $cname, context => { cluster => $cname, user => $user } } ],
    'current-context' => $cname,
  } );
}

1;

__END__

=head1 DESCRIPTION

Helper behind C<ocp kubeconfig --readonly>. It applies a ServiceAccount
C<ocp-readonly-NAME> in C<ocp-system>, bound to the built-in ClusterRole
C<view> and to C<ocp-readonly> (get/list/watch on Nodes, OCPNodes and
OCPNodeProviders), plus a C<kubernetes.io/service-account-token> Secret whose
token ends up in the kubeconfig. Nothing is stored locally. See
L<OCP::Cmd::Kubeconfig>.

=cut
