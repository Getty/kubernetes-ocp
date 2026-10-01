package OCP::NodeMeta;
# ABSTRACT: Node labels and taints from an OCPNode spec -- syntax, join labels, convergence

use strict;
use warnings;

use Carp qw( croak );
use JSON::MaybeXS ();

# One place for what an OCPNode's spec.labels / spec.taints mean (k211):
# ocp.yaml worker pools and `ocp node add --label/--taint` write them, the
# install hands the labels the kubelet may set itself to the join, and
# OCP::Node converges the Kubernetes Node object to both afterwards.

our @TAINT_EFFECTS = qw( NoSchedule PreferNoSchedule NoExecute );

# Which keys OCP set on the Node last time, so a key dropped from the spec is
# removed again -- and nothing set by someone else ever is.
our $MANAGED_LABELS_ANNOTATION = 'ocp.internal/managed-labels';
our $MANAGED_TAINTS_ANNOTATION = 'ocp.internal/managed-taints';

# Which labels and taints of an OCPNode's spec its worker pool in ocp.yaml put
# there, so `ocp apply` can take back what the pool dropped (k211).
our $POOL_LABELS_ANNOTATION = 'ocp.internal/pool-labels';
our $POOL_TAINTS_ANNOTATION = 'ocp.internal/pool-taints';

my $NAME_RE   = qr/[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?/;
my $PREFIX_RE = qr/[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*/;

# A label or taint key: [prefix/]name, Kubernetes' qualified-name syntax.
sub valid_key {
  my ( $self, $key ) = @_;
  return 0 unless defined $key && !ref $key;
  my ( $prefix, $name ) = $key =~ m{/} ? split( m{/}, $key, 2 ) : ( undef, $key );
  return 0 if defined $prefix && ( length $prefix > 253 || $prefix !~ /\A$PREFIX_RE\z/ );
  return $name =~ /\A$NAME_RE\z/ ? 1 : 0;
}

# A label value: empty, or up to 63 name characters.
sub valid_value {
  my ( $self, $value ) = @_;
  return 0 unless defined $value && !ref $value;
  return 1 if $value eq '';
  return $value =~ /\A$NAME_RE\z/ ? 1 : 0;
}

# Errors for a labels mapping, each prefixed with $where.
sub label_errors {
  my ( $self, $where, $labels ) = @_;
  return ( $where.': must be a mapping of label => value' ) unless ref $labels eq 'HASH';
  my @errors;
  for my $k ( sort keys %$labels ) {
    my $v = $labels->{$k};
    push @errors, $where.": '".$k."' is not a valid label key" unless $self->valid_key($k);
    if ( ref $v || !defined $v ) {
      push @errors, $where.'.'.$k.': value must be a string (quote true, false and numbers)';
    }
    elsif ( !$self->valid_value($v) ) {
      push @errors, $where.'.'.$k.": '".$v."' is not a valid label value";
    }
  }
  return @errors;
}

# "key=value:Effect" or "key:Effect", the kubectl taint syntax: what is wrong
# with it, or undef when nothing is.
sub taint_error {
  my ( $self, $str ) = @_;
  return 'taint must be a string like key=value:NoSchedule' unless defined $str && !ref $str;
  my ( $kv, $effect ) = $str =~ /\A(.+):([^:=]+)\z/
    or return "taint '".$str."': expected key=value:Effect or key:Effect";
  return "taint '".$str."': effect must be ".join( ', ', @TAINT_EFFECTS )
    unless grep { $_ eq $effect } @TAINT_EFFECTS;
  my ( $key, $value ) = $kv =~ /=/ ? split( /=/, $kv, 2 ) : ( $kv, undef );
  return "taint '".$str."': '".$key."' is not a valid key" unless $self->valid_key($key);
  return "taint '".$str."': '".$value."' is not a valid value"
    if defined $value && !$self->valid_value($value);
  return undef;
}

# The same string into the OCPNode CRD's { key, value, effect }. Croaks with
# taint_error's reason.
sub parse_taint {
  my ( $self, $str ) = @_;
  if ( defined( my $err = $self->taint_error($str) ) ) { croak $err }
  my ( $kv, $effect ) = $str =~ /\A(.+):([^:=]+)\z/;
  my ( $key, $value ) = $kv =~ /=/ ? split( /=/, $kv, 2 ) : ( $kv, undef );
  return {
    key    => $key,
    ( defined $value && length $value ? ( value => $value ) : () ),
    effect => $effect,
  };
}

# "key=value": what is wrong with it, or undef.
sub label_error {
  my ( $self, $str ) = @_;
  return 'label must be a string like key=value' unless defined $str && !ref $str;
  my ( $key, $value ) = $str =~ /\A([^=]+)=(.*)\z/
    or return "label '".$str."': expected key=value";
  return "label '".$str."': '".$key."' is not a valid key"     unless $self->valid_key($key);
  return "label '".$str."': '".$value."' is not a valid value" unless $self->valid_value($value);
  return undef;
}

# "key=value" -> ( key => value ). Croaks with label_error's reason.
sub parse_label {
  my ( $self, $str ) = @_;
  if ( defined( my $err = $self->label_error($str) ) ) { croak $err }
  my ( $key, $value ) = $str =~ /\A([^=]+)=(.*)\z/;
  return ( $key => $value );
}

# ocp.yaml's pool labels / taints in OCPNode spec shape: label values as
# strings, taints parsed from "key=value:Effect". Empty when none are set;
# OCP::Config->validate has reported anything malformed before.
sub spec_labels {
  my ( $self, $labels ) = @_;
  return {} unless ref $labels eq 'HASH';
  return { map { $_ => ''.$labels->{$_} } grep { defined $labels->{$_} && !ref $labels->{$_} } keys %$labels };
}

sub spec_taints {
  my ( $self, $taints ) = @_;
  return [] unless ref $taints eq 'ARRAY';
  return [ map { $self->parse_taint($_) } @$taints ];
}

# Identity of a taint on a Node: key and effect, as Kubernetes keys them.
sub taint_id { my ( $self, $t ) = @_; return $t->{key}.':'.$t->{effect} }

# Whether the kubelet may set this label on its own Node at registration.
# The NodeRestriction admission plugin refuses kubernetes.io / k8s.io keys
# outside a short allowed list, and refuses the whole registration with them
# -- such a label goes to the Node through the API only, after the join.
my %KUBELET_ALLOWED = map { $_ => 1 } qw(
  kubernetes.io/hostname kubernetes.io/arch kubernetes.io/os
  beta.kubernetes.io/instance-type node.kubernetes.io/instance-type
  failure-domain.beta.kubernetes.io/region failure-domain.beta.kubernetes.io/zone
  topology.kubernetes.io/region topology.kubernetes.io/zone
);

sub kubelet_may_set {
  my ( $self, $key ) = @_;
  return 1 if $KUBELET_ALLOWED{$key};
  my ($prefix) = $key =~ m{\A([^/]+)/} or return 1;
  return 1 if $prefix =~ /(?:\A|\.)(?:kubelet|node)\.kubernetes\.io\z/;
  return $prefix =~ /(?:\A|\.)(?:kubernetes\.io|k8s\.io)\z/ ? 0 : 1;
}

# The labels for the join (Rex::Rancher's node_labels), as sorted key=value
# strings: those the kubelet may set itself.
sub join_labels {
  my ( $self, $labels ) = @_;
  return [] unless ref $labels eq 'HASH';
  return [ map { $_.'='.$labels->{$_} } grep { $self->kubelet_may_set($_) } sort keys %$labels ];
}

sub _json { JSON::MaybeXS->new( canonical => 1 ) }

sub _managed {
  my ( $self, $meta, $annotation ) = @_;
  my $raw = ( $meta->{annotations} // {} )->{$annotation};
  return () unless defined $raw && length $raw;
  my $list = eval { $self->_json->decode($raw) };
  return ref $list eq 'ARRAY' ? @$list : ();
}

sub _taint_norm {
  my ( $self, $t ) = @_;
  return {
    key    => $t->{key},
    effect => $t->{effect},
    ( defined $t->{value} && length $t->{value} ? ( value => $t->{value} ) : () ),
  };
}

# The merge both patches below share: what a labels map and a taints list
# carrying $have_labels / $have_taints become, when OCP previously set the
# label keys @$prev_labels and the taint ids @$prev_taints and now wants
# $want_labels / $want_taints. What OCP did not set is kept; what it set and
# no longer wants goes. Returns the label changes for a merge patch (undef =
# remove), the whole new taints list (or undef when unchanged) and the new
# bookkeeping lists.
sub _merge {
  my ( $self, %a ) = @_;
  my %have = %{ $a{have_labels} // {} };
  my %want = %{ $a{want_labels} // {} };
  my $json = $self->_json;

  my %labels;
  for my $k ( keys %want ) {
    $labels{$k} = $want{$k} unless defined $have{$k} && $have{$k} eq $want{$k};
  }
  for my $k ( @{ $a{prev_labels} } ) {
    $labels{$k} = undef if !exists $want{$k} && exists $have{$k};
  }

  my @have_t = @{ $a{have_taints} // [] };
  my %prev_t = map { $_ => 1 } @{ $a{prev_taints} };
  my %want_t = map { $self->taint_id($_) => $self->_taint_norm($_) } @{ $a{want_taints} // [] };
  my @taints = (
    ( grep { my $id = $self->taint_id($_); !$prev_t{$id} && !$want_t{$id} } @have_t ),
    ( map { $want_t{$_} } sort keys %want_t ),
  );
  my $canon = sub { $json->encode( [ sort map { $json->encode( $self->_taint_norm($_) ) } @_ ] ) };

  return (
    \%labels,
    ( $canon->(@taints) ne $canon->(@have_t) ? \@taints : undef ),
    [ sort keys %want ],
    [ sort keys %want_t ],
  );
}

# Annotation changes for a merge patch: each name in %$lists to its JSON list,
# removed when the list is empty, left out when it already reads that way.
sub _bookkeeping {
  my ( $self, $meta, %lists ) = @_;
  my %annotations;
  for my $a ( sort keys %lists ) {
    my $now = ( $meta->{annotations} // {} )->{$a};
    my $new = @{ $lists{$a} } ? $self->_json->encode( $lists{$a} ) : undef;
    next if ( $now // '' ) eq ( $new // '' );
    $annotations{$a} = $new;
  }
  return \%annotations;
}

# The JSON merge patch that brings a Node (as a struct) to the wanted labels
# and taints, or undef when it already carries them. Labels and taints OCP did
# not set (not in the managed annotations) are left alone; ones OCP set and the
# spec no longer has are removed. The patch carries the Node's resourceVersion,
# so a concurrent writer makes it fail with 409 instead of being overwritten.
sub converge_patch {
  my ( $self, $node, $want_labels, $want_taints ) = @_;
  my $meta = $node->{metadata} // {};

  my ( $labels, $taints, $label_keys, $taint_ids ) = $self->_merge(
    have_labels => $meta->{labels},
    have_taints => ( $node->{spec} // {} )->{taints},
    prev_labels => [ $self->_managed( $meta, $MANAGED_LABELS_ANNOTATION ) ],
    prev_taints => [ $self->_managed( $meta, $MANAGED_TAINTS_ANNOTATION ) ],
    want_labels => $want_labels,
    want_taints => $want_taints,
  );
  my $annotations = $self->_bookkeeping( $meta,
    $MANAGED_LABELS_ANNOTATION => $label_keys,
    $MANAGED_TAINTS_ANNOTATION => $taint_ids,
  );

  return undef unless %$labels || %$annotations || $taints;
  return {
    metadata => {
      resourceVersion => $meta->{resourceVersion},
      ( %$labels      ? ( labels      => $labels )      : () ),
      ( %$annotations ? ( annotations => $annotations ) : () ),
    },
    ( $taints ? ( spec => { taints => $taints } ) : () ),
  };
}

# The same for an OCPNode's spec.labels / spec.taints against its worker
# pool in ocp.yaml (k211): the merge patch `ocp apply` sends to an OCPNode
# that already exists, or undef. Removes only what the pool put there itself
# (the pool-* annotations, written with the OCPNode too); labels and taints
# from `kubectl edit ocpnode` or `ocp node add` stay. An OCPNode without that
# bookkeeping loses nothing -- its origin is unknown.
sub spec_patch {
  my ( $self, $ocpnode, $want_labels, $want_taints ) = @_;
  my $meta = $ocpnode->{metadata} // {};
  my $spec = $ocpnode->{spec} // {};

  my ( $labels, $taints, $label_keys, $taint_ids ) = $self->_merge(
    have_labels => $spec->{labels},
    have_taints => $spec->{taints},
    prev_labels => [ $self->_managed( $meta, $POOL_LABELS_ANNOTATION ) ],
    prev_taints => [ $self->_managed( $meta, $POOL_TAINTS_ANNOTATION ) ],
    want_labels => $want_labels,
    want_taints => $want_taints,
  );
  my $annotations = $self->_bookkeeping( $meta,
    $POOL_LABELS_ANNOTATION => $label_keys,
    $POOL_TAINTS_ANNOTATION => $taint_ids,
  );

  return undef unless %$labels || %$annotations || $taints;
  my %spec = (
    ( %$labels ? ( labels => $labels ) : () ),
    ( $taints  ? ( taints => $taints ) : () ),
  );
  return {
    metadata => {
      resourceVersion => $meta->{resourceVersion},
      ( %$annotations ? ( annotations => $annotations ) : () ),
    },
    ( %spec ? ( spec => \%spec ) : () ),
  };
}

# The pool-* annotations a new OCPNode starts with, for the labels and taints
# (spec shape) the pool gives it. Empty when it gives none.
sub pool_annotations {
  my ( $self, $labels, $taints ) = @_;
  return $self->_bookkeeping( {},
    $POOL_LABELS_ANNOTATION => [ sort keys %{ $labels // {} } ],
    $POOL_TAINTS_ANNOTATION => [ sort map { $self->taint_id($_) } @{ $taints // [] } ],
  );
}

1;

__END__

=head1 SYNOPSIS

  my $taint = OCP::NodeMeta->parse_taint('nvidia.com/gpu=present:NoSchedule');
  my %label = OCP::NodeMeta->parse_label('ai.citilan.de/node-class=rtx3090');

  my $join  = OCP::NodeMeta->join_labels($cr->{spec}{labels});   # [ 'k=v', ... ]
  my $patch = OCP::NodeMeta->converge_patch($node_struct,
    $cr->{spec}{labels}, $cr->{spec}{taints});

=head1 DESCRIPTION

What an OCPNode's C<spec.labels> and C<spec.taints> mean, in one place.
L<OCP::Config> validates them in F<ocp.yaml> worker pools, C<ocp node add>
parses C<--label> and C<--taint>, and L<OCP::Node> hands the labels to the join
and converges the Kubernetes Node object to both once it is registered.

=method parse_label

C<key=value> into a one-pair list. Dies naming what is wrong.

=method parse_taint

C<key=value:Effect> or C<key:Effect> into C<{ key, value, effect }>. The effect
is one of C<NoSchedule>, C<PreferNoSchedule>, C<NoExecute>.

=method label_error / taint_error

What is wrong with a C<--label> / C<--taint> string, or undef. For messages
that go to a user as they are.

=method spec_labels / spec_taints

An F<ocp.yaml> worker pool's C<labels> mapping and C<taints> list in OCPNode
spec shape.

=method label_errors

  my @errors = OCP::NodeMeta->label_errors('workers[1].labels', $labels);

=method join_labels

The labels the kubelet may set on itself at registration, as sorted
C<key=value> strings. Keys under C<kubernetes.io> or C<k8s.io> other than the
few the NodeRestriction admission plugin allows would make the registration
fail; they reach the Node through L</converge_patch> only.

=method spec_patch

  my $patch = OCP::NodeMeta->spec_patch($ocpnode_struct,
    $pool_spec->{labels}, $pool_spec->{taints});

A JSON merge patch for an OCPNode that brings its C<spec.labels> and
C<spec.taints> to its worker pool's, or undef. The pool's own entries are
recorded in C<ocp.internal/pool-labels> and C<ocp.internal/pool-taints>; only
those are ever removed, so what C<kubectl edit ocpnode> or C<ocp node add>
added stays. An OCPNode without the annotations loses nothing.

=method pool_annotations

The C<ocp.internal/pool-*> annotations a new OCPNode starts with.

=method converge_patch

A JSON merge patch for the Node, or undef when nothing is to change. OCP
records the label keys and taints it manages in the annotations
C<ocp.internal/managed-labels> and C<ocp.internal/managed-taints>; only those
are ever removed. Taints are matched by key and effect.

=cut
