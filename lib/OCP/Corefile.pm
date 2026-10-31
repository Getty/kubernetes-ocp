package OCP::Corefile;
# ABSTRACT: A CoreDNS Corefile read as server blocks -- which one answers a name, and with what address

use Moo;
use namespace::clean;

# One reading of the Corefile for both sides of the registry.local record
# (k338): OCP::Cmd::Apply::Network writes it, OCP::Drift's registry_dns_drift
# checks it. Each used to read the file its own way -- the writer looked only
# at the root block, the probe took the first record anywhere -- and on a
# Corefile where the two differ the step failed while the probe saw nothing
# wrong. Both now ask this class which block answers the name.

has text => ( is => 'ro', required => 1 );

# The lines as split /\n/, -1 leaves them: joined with "\n", the text again.
has lines => ( is => 'lazy', init_arg => undef );

# Brace depth at the start of each line: 0 on a server block header, 1 on the
# plugin lines inside it, 2 inside a plugin's config block.
has depth => ( is => 'lazy', init_arg => undef );

# The server blocks in file order, each { keys, zones, root, from, to }: the
# header's keys as written, the zones they serve, whether one is the root
# zone, and the lines of the header and of the closing brace.
has blocks => ( is => 'lazy', init_arg => undef );

sub _build_lines {
  my ( $self ) = @_;
  return [ split /\n/, $self->text, -1 ];
}

sub _build_depth {
  my ( $self ) = @_;
  my @depth;
  my $level = 0;
  for my $line ( @{ $self->lines } ) {
    push @depth, $level;
    my $opens  = () = $line =~ /\{/g;
    my $closes = () = $line =~ /\}/g;
    $level += $opens - $closes;
  }
  return \@depth;
}

sub _build_blocks {
  my ( $self ) = @_;
  my ( $lines, $depth ) = ( $self->lines, $self->depth );

  my @blocks;
  for my $i ( 0 .. $#$lines ) {
    next unless $depth->[$i] == 0 && $lines->[$i] =~ /^(.*?)\{\s*$/;
    my @keys = split ' ', $1;

    # Closed by the first lone brace one level in; never closed, no block
    my ( $to ) = grep { $depth->[$_] == 1 && $lines->[$_] =~ /^\s*\}\s*$/ } $i + 1 .. $#$lines;
    next unless defined $to;

    my @zones = map { $self->zone($_) } @keys;
    push @blocks, {
      keys  => \@keys,
      zones => \@zones,
      root  => ( grep { $_ eq '.' } @zones ) ? 1 : 0,
      from  => $i,
      to    => $to,
    };
  }

  return \@blocks;
}

# The zone a server block key serves, lowercase and without its trailing dot,
# '.' for the root zone ('.', '.:53', 'dns://.:53'). Nothing for a key that
# names none, a reverse CIDR or a bare port. Scheme and port are read past,
# not compared, as the root block was always found.
sub zone {
  my ( $self, $key ) = @_;
  my ( $zone ) = $key =~ m{^(?:[a-z]+://)?([^:/\s]+)(?::\d+)?$} or return;
  return '.' if $zone eq '.';
  $zone =~ s/\.\z//;
  return if $zone eq '' || $zone =~ /^\./;
  return lc $zone;
}

# The server block CoreDNS answers $name from: of the blocks with a zone that
# covers the name, the one with the most specific zone, the root zone covering
# every name. The first in the file on a tie, undef when none covers it.
sub block_for {
  my ( $self, $name ) = @_;
  $name = lc $name;
  $name =~ s/\.\z// unless $name eq '.';

  my ( $best, $best_length );
  for my $block ( @{ $self->blocks } ) {
    for my $zone ( @{ $block->{zones} } ) {
      next unless $zone eq '.' || $name eq $zone || $name =~ /\.\Q$zone\E\z/;
      my $length = $zone eq '.' ? 0 : length $zone;
      next if defined $best_length && $length <= $best_length;
      ( $best, $best_length ) = ( $block, $length );
    }
  }

  return $best;
}

# The first server block for the root zone, the one OCP writes records into.
sub root_block { shift->block_for('.') }

# A hosts plugin record: ( $address, @names ), or nothing for any other line.
# The first token is an address, not a plugin name: hex digits, dots and
# colons only, and at least one separator (`cache 30` is not a record).
sub record {
  my ( $self, $line ) = @_;
  my @token = split ' ', $line;
  return unless @token >= 2 && $token[0] =~ /^[0-9a-fA-F.:]+$/ && $token[0] =~ /[.:]/;
  return @token;
}

# The line of the first record in $block that lists $name, or undef: the
# record CoreDNS answers with, and the one the writer corrects in place.
sub record_index {
  my ( $self, $block, $name ) = @_;
  my $lines = $self->lines;
  for my $i ( $block->{from} + 1 .. $block->{to} - 1 ) {
    my ( undef, @names ) = $self->record( $lines->[$i] ) or next;
    return $i if grep { $_ eq $name } @names;
  }
  return;
}

# The address the block that answers for $name maps it to, or undef when no
# block answers or it maps nothing.
sub address_of {
  my ( $self, $name ) = @_;
  my $block = $self->block_for($name) or return;
  my $i = $self->record_index( $block, $name ) // return;
  my ( $address ) = $self->record( $self->lines->[$i] );
  return $address;
}

1;

__END__

=head1 SYNOPSIS

  my $corefile = OCP::Corefile->new( text => $cm->data->{Corefile} );

  my $block = $corefile->block_for('registry.local');   # the block that answers
  print "answered from the root block\n" if $block && $block->{root};
  my $ip = $corefile->address_of('registry.local');     # what it answers with

=head1 DESCRIPTION

A CoreDNS Corefile as server blocks, read the way CoreDNS picks one: a name is
answered by the block whose zone covers it most specifically, the root zone
covering every name. The registry.local writer in L<OCP::Cmd::Apply::Network>
and the probe in L<OCP::Drift> both read the Corefile through this class, so
they cannot disagree about where the record is or what it says.

=attr text

The Corefile. Required.

=attr lines

L</text> split into lines; joined with C<"\n">, the text again.

=attr depth

The brace depth at the start of each line: 0 on a server block header, 1 on
the plugin lines inside it.

=attr blocks

The server blocks in file order, as C<{ keys, zones, root, from, to }>: the
header's keys, the zones they serve, whether one is the root zone, and the
line indexes of the header and of the closing brace.

=method block_for

  my $block = $corefile->block_for('registry.local');

The server block that answers for the name, or undef when none does.

=method root_block

The first server block for the root zone, or undef.

=method address_of

  my $ip = $corefile->address_of('registry.local');

The address the answering block's hosts plugin maps the name to, or undef.

=method record_index

  my $i = $corefile->record_index( $block, 'registry.local' );

The index in L</lines> of the first record in the block that lists the name,
or undef.

=method record

  my ( $address, @names ) = $corefile->record($line);

A hosts plugin record line split into its address and names; nothing for any
other line.

=method zone

The zone a server block key serves (C<registry.local:53> is
C<registry.local>, C<dns://.:53> the root zone C<.>), or nothing.

=cut
