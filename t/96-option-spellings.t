#!/usr/bin/env perl
use strict;
use warnings;

# MooX::Options answers a usage error with exit(); make that catchable, so a
# rejected spelling fails one test instead of ending the file.
BEGIN {
  *CORE::GLOBAL::exit = sub { die 'EXIT(' . ( $_[0] // 0 ) . ")\n" };
}

use Test::More;
use Module::Runtime qw( use_module );

use OCP;

# k167 — every multi-word option takes both spellings, --pins-stdin and
# --pins_stdin, wherever it stands on the command line.
#
# The live failure was `ocp init --provider ssh --host x --force --pins-stdin`
# dying with "Unknown option: pins-stdin" while `--pins_stdin` worked, and
# while `--pins-stdin` on its own worked too. MooX::Options (4.103) rewrites
# dashes to underscores in _options_fix_argv, but that loop takes the argument
# after EVERY known option as that option's value -- a boolean included -- and
# passes it on untouched. So the dashed spelling only survived when the option
# before it took a value (or there was none). OCP::Role::Cmd normalizes the
# spelling before MooX::Options sees the vector.
#
# The claims, for every option of every command reachable from `ocp` (the
# list is derived from the classes, not written down here):
#
#   * alone, the dashed and the underscored spelling both parse
#   * directly after any other option of the same command -- boolean or with
#     a value -- both spellings still parse, and the option before keeps its
#     value
#   * a dashed spelling of an option the command does not have is still
#     rejected: normalizing is not accepting anything

# Every command class reachable from the root, root included.
sub command_classes {
  my @todo = ('OCP');
  my @all;
  while ( my $class = shift @todo ) {
    use_module($class);
    push @all, $class;
    push @todo, sort values %{ OCP::_command_map($class) };
  }
  return @all;
}

# argv words for giving option $name of $class, spelled $spelling.
sub words_for {
  my ( $data, $name, $spelling ) = @_;

  my $flag = '--' . $name;
  $flag =~ tr/_/-/ if $spelling eq 'dashed';

  my $format = $data->{$name}{format};
  return ($flag) unless defined $format;
  return ( $flag, $format =~ /\Ai/ ? '7' : 'val' );
}

# parse_options with @ARGV set to @argv: the parsed hash, or the error text.
sub parse {
  my ( $class, @argv ) = @_;

  my ( %got, $err );
  my $stderr = '';
  {
    local @ARGV = @argv;
    local *STDERR;
    open STDERR, '>', \$stderr or die "stderr: $!";
    local *STDOUT;
    my $stdout = '';
    open STDOUT, '>', \$stdout or die "stdout: $!";
    %got = eval { $class->parse_options };
    $err = $@;
  }
  return $err ? ( undef, $err . $stderr ) : ( \%got, '' );
}

my @classes = command_classes();
ok( scalar(@classes) > 10, 'found the command classes: ' . scalar(@classes) );

my $multi_word = 0;

for my $class (@classes) {
  my %data = $class->_options_data;
  my @names = sort keys %data;

  for my $name ( grep { /_/ } @names ) {
    $multi_word++;

    for my $spelling (qw( dashed underscored )) {
      my @words = words_for( \%data, $name, $spelling );

      my ( $got, $err ) = parse( $class, @words );
      ok( $got && defined $got->{$name}, "$class: @words alone" )
        or diag $err;

      for my $before ( grep { $_ ne $name } @names ) {
        my @prefix = words_for( \%data, $before, 'underscored' );
        my ( $got, $err ) = parse( $class, @prefix, @words );
        ok(
          $got && defined $got->{$name} && defined $got->{$before},
          "$class: @prefix @words"
        ) or diag $err;
      }
    }
  }
}

ok( $multi_word >= 10, 'checked every multi-word option: ' . $multi_word );

# A negatable option keeps its --no- form in any position.
for my $class ( grep { my %d = $_->_options_data; grep { $_->{negatable} } values %d } @classes ) {
  my %data = $class->_options_data;
  for my $name ( grep { $data{$_}{negatable} } sort keys %data ) {
    ( my $dashed = $name ) =~ tr/_/-/;
    my ( $got, $err ) = parse( $class, '--pins-stdin', '--no-' . $dashed );
    ok( $got && defined $got->{$name} && !$got->{$name},
      "$class: --pins-stdin --no-$dashed negates" ) or diag $err;
  }
}

{
  my ( $got, $err ) = parse( 'OCP::Cmd::Init', '--force', '--not-an-option' );
  ok( !$got, 'an unknown dashed option is still rejected' );
  like( $err, qr/Unknown option: not/, '... by Getopt::Long, naming it' );
}

done_testing;
