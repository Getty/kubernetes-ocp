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

# The files a top-level `import` reads, as { path => text } (k348): k3s
# mounts its coredns-custom ConfigMap at /etc/coredns/custom and its stock
# Corefile imports the *.server keys from there as server blocks of their
# own, which answer names like the Corefile's own blocks. None by default.
has imports => ( is => 'ro', default => sub { {} } );

# The lines as split /\n/, -1 leaves them, each top-level `import` followed by
# the lines of the files it reads: without imports, joined with "\n", the
# text again.
has lines => ( is => 'lazy', init_arg => undef );

# Where each line of lines comes from: undef for the text, the path of the
# file for a line an import read in.
has origin => ( is => 'lazy', init_arg => undef );

has _expanded => ( is => 'lazy', init_arg => undef );

# Brace depth at the start of each line: 0 on a server block header, 1 on the
# plugin lines inside it, 2 inside a plugin's config block.
has depth => ( is => 'lazy', init_arg => undef );

# The server blocks in file order, each { keys, zones, root, from, to, file }:
# the header's keys as written, the zones they serve on the cluster's port,
# whether one is the root zone, the lines of the header and of the closing
# brace, and the file an import read the block from (undef: the text).
has blocks => ( is => 'lazy', init_arg => undef );

sub _build_lines  { shift->_expanded->[0] }
sub _build_origin { shift->_expanded->[1] }

# CoreDNS puts what a top-level import reads where the import stands, the
# files a glob matches in name order (Go's filepath.Glob sorts them).
sub _build__expanded {
  my ( $self ) = @_;
  my $imports = $self->imports;

  my ( @lines, @origin );
  my $level = 0;
  for my $line ( split /\n/, $self->text, -1 ) {
    push @lines, $line;
    push @origin, undef;
    if ( $level == 0 && ( my ( $pattern ) = $line =~ /^\s*import\s+(\S+)/ ) ) {
      for my $path ( sort grep { $self->_glob_matches( $pattern, $_ ) } keys %$imports ) {
        my @file = split /\n/, $imports->{$path} // '', -1;
        push @lines, @file;
        push @origin, ($path) x @file;
      }
    }
    $level += $self->_braces($line);
  }

  return [ \@lines, \@origin ];
}

# What a line does to the brace depth: its opening braces less its closing ones.
sub _braces {
  my ( $self, $line ) = @_;
  my $opens  = () = $line =~ /\{/g;
  my $closes = () = $line =~ /\}/g;
  return $opens - $closes;
}

# Whether $path is a file the import pattern $pattern reads: * and ? match
# within one path segment, everything else (character classes too) only itself.
sub _glob_matches {
  my ( $self, $pattern, $path ) = @_;
  my $re = join '', map { $_ eq '*' ? '[^/]*' : $_ eq '?' ? '[^/]' : quotemeta } split //, $pattern;
  return $path =~ /\A$re\z/ ? 1 : 0;
}

sub _build_depth {
  my ( $self ) = @_;
  my @depth;
  my $level = 0;
  for my $line ( @{ $self->lines } ) {
    push @depth, $level;
    $level += $self->_braces($line);
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

    my @zones = map { $self->zone($_) } grep { $self->on_cluster_port($_) } @keys;
    push @blocks, {
      keys  => \@keys,
      zones => \@zones,
      root  => ( grep { $_ eq '.' } @zones ) ? 1 : 0,
      from  => $i,
      to    => $to,
      file  => $self->origin->[$i],
    };
  }

  return \@blocks;
}

# The zone a server block key serves, lowercase and without its trailing dot,
# '.' for the root zone ('.', '.:53', 'dns://.:53'). Nothing for a key that
# names none, a reverse CIDR or a bare port. Scheme and port are read past
# here; on_cluster_port is what compares them.
sub zone {
  my ( $self, $key ) = @_;
  my ( $zone ) = $key =~ m{^(?:[a-z]+://)?([^:/\s]+)(?::\d+)?$} or return;
  return '.' if $zone eq '.';
  $zone =~ s/\.\z//;
  return if $zone eq '' || $zone =~ /^\./;
  return lc $zone;
}

# Whether a server block key listens where the cluster asks: plain DNS (no
# scheme, or dns://) on port 53, CoreDNS' default. Both distributions'
# Corefiles say .:53, and the kube-dns Service sends to 53; a block on another
# port or transport answers none of the cluster's queries, so it neither
# answers a name nor shadows the root block (k348).
sub on_cluster_port {
  my ( $self, $key ) = @_;
  my ( $scheme, $port ) = $key =~ m{^(?:([a-z]+)://)?[^:/\s]+(?::(\d+))?$} or return 0;
  return 0 if defined $scheme && $scheme ne 'dns';
  return 0 if defined $port && $port != 53;
  return 1;
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

# The lines in $block that run the hosts plugin. CoreDNS takes it once per
# server block and refuses the whole Corefile over a second one ("plugin/hosts:
# this plugin can only be used once per Server Block").
sub hosts_lines {
  my ( $self, $block ) = @_;
  my ( $lines, $depth ) = ( $self->lines, $self->depth );
  return grep { $depth->[$_] == 1 && $lines->[$_] =~ /^\s*hosts\b/ } $block->{from} + 1 .. $block->{to} - 1;
}

# The first server block that runs the hosts plugin more than once, or undef.
# Any block, whatever its zone, port or file: CoreDNS sets up every block it
# reads and refuses the whole Corefile over one of them, so a doubled hosts
# plugin in a block that answers nothing the cluster asks breaks the name all
# the same (k393).
sub doubled_hosts_block {
  my ( $self ) = @_;
  for my $block ( @{ $self->blocks } ) {
    return $block if ( () = $self->hosts_lines($block) ) > 1;
  }
  return;
}

# The text without the hosts blocks an older OCP added to the root block next
# to the distribution's own: a hosts plugin that names no file and lists
# $name. Only while the root block runs the plugin more than once, and never
# the last one standing. The writer repairs that Corefile with it, the probe
# asks whether the repair is enough (k348). Reads the text, not its imports.
sub without_added_hosts {
  my ( $self, $name ) = @_;
  return ref($self)->new( text => $self->text )->without_added_hosts($name) if %{ $self->imports };

  my @lines = @{ $self->lines };
  my @depth = @{ $self->depth };

  my $root = $self->root_block or return $self->text;
  my @hosts = $self->hosts_lines($root);
  return $self->text if @hosts < 2;

  my $left = scalar @hosts;
  for my $i ( reverse @hosts ) {
    last if $left < 2;
    next unless $lines[$i] =~ /^\s*hosts\s*\{\s*$/;

    my $end = $i;
    $end++ while $end < $root->{to} && $depth[ $end + 1 ] > $depth[$i];
    next unless grep { /\b\Q$name\E\b/ } @lines[ $i + 1 .. $end ];

    splice @lines, $i, $end - $i + 1;
    $left--;
  }

  return join "\n", @lines;
}

# The patterns of the imports at the top level of the text, the ones that
# read server blocks.
sub import_patterns {
  my ( $self ) = @_;
  my ( $lines, $depth, $origin ) = ( $self->lines, $self->depth, $self->origin );
  return map { $lines->[$_] =~ /^\s*import\s+(\S+)/ ? $1 : () }
    grep { $depth->[$_] == 0 && !defined $origin->[$_] } 0 .. $#$lines;
}

1;

__END__

=head1 SYNOPSIS

  my $corefile = OCP::Corefile->new( text => $cm->data->{Corefile} );

  my $block = $corefile->block_for('registry.local');   # the block that answers
  print "answered from the root block\n" if $block && $block->{root};
  my $ip = $corefile->address_of('registry.local');     # what it answers with

  # With the server blocks a top-level import reads in
  my $k3s = OCP::Corefile->new(
    text    => $cm->data->{Corefile},
    imports => { '/etc/coredns/custom/registry.server' => $snippet },
  );

=head1 DESCRIPTION

A CoreDNS Corefile as server blocks, read the way CoreDNS picks one: a name is
answered by the block whose zone covers it most specifically, the root zone
covering every name. The registry.local writer in L<OCP::Cmd::Apply::Network>
and the probe in L<OCP::Drift> both read the Corefile through this class, so
they cannot disagree about where the record is or what it says.

Only plain DNS on port 53 answers the cluster's queries (L</on_cluster_port>),
and a top-level C<import> reads the server blocks of the files given as
L</imports> in where it stands, as CoreDNS does.

=attr text

The Corefile. Required.

=attr imports

The files a top-level C<import> reads, as C<{ path =E<gt> text }>; none by
default. An import's pattern reads the paths it matches (C<*> and C<?> within
one path segment), in name order. An import inside a server block is not
read.

=attr lines

L</text> split into lines, each top-level C<import> followed by the lines of
the files it reads. Without L</imports>, joined with C<"\n">, the text again.

=attr origin

Per line of L</lines>, the path of the file an import read it from, or undef
for a line of the text.

=attr depth

The brace depth at the start of each line: 0 on a server block header, 1 on
the plugin lines inside it.

=attr blocks

The server blocks in file order, as C<{ keys, zones, root, from, to, file }>:
the header's keys, the zones they serve on the cluster's port, whether one is
the root zone, the line indexes of the header and of the closing brace, and
the file an import read the block from (undef for the text's own).

=method block_for

  my $block = $corefile->block_for('registry.local');

The server block CoreDNS answers the name from, or undef when none does. Of
the blocks with a zone that covers the name (the zone itself or a name below
it, compared in lowercase and without a trailing dot), the one with the most
specific zone wins; the root zone covers every name and is the least specific.
On a tie the first block in the file wins. Blocks whose keys are not on the
cluster's port have no zone and never answer (L</on_cluster_port>).

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

=method on_cluster_port

  $corefile->on_cluster_port('registry.local:5353');   # 0

Whether a server block key listens for plain DNS on port 53, where the
cluster's queries arrive. A block whose keys do not serves no zone in
L</blocks>.

=method hosts_lines

  my @at = $corefile->hosts_lines( $corefile->root_block );

The indexes in L</lines> of the block's hosts plugin lines. More than one is a
Corefile CoreDNS refuses.

=method doubled_hosts_block

  my $block = $corefile->doubled_hosts_block;

The first server block in L</blocks> that runs the hosts plugin more than
once, or undef. Every block counts, on any port and imported or not: CoreDNS
refuses the whole Corefile over any one of them.

=method without_added_hosts

  my $text = $corefile->without_added_hosts('registry.local');

The text without the hosts blocks an older OCP added to the root block next to
the distribution's own (no file, lists the name), while the root block runs
the plugin more than once; never the last one. Reads the text without its
imports.

=method import_patterns

The patterns of the text's top-level C<import> lines.

=cut
