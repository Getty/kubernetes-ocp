package OCPTest::Cli;
# ABSTRACT: ocp run as bin/ocp runs it, and the leaf commands it dispatches to

use strict;
use warnings;
use Exporter 'import';
use File::Temp qw( tempdir );
use Module::Runtime qw( use_module );
use POSIX ();
use Path::Tiny qw( path );

use OCP;

our @EXPORT_OK = qw( run_ocp leaf_commands required_options );

# Moved out of t/398-one-error-renderer.t (k400) as they stood there, so that
# t/400 (every command on every malformed path) runs the commands the way
# t/398 runs them.

# `ocp @argv` the way bin/ocp runs it -- OCP->run_cli -- in a child, in $dir,
# STDIN empty; $setup runs in the child first, so what it replaces stays
# there. The child's END is the first to run and ends it at once: none of this
# file's own END blocks, and no global destruction, run in the child.
sub run_ocp {
    my ($dir, $setup, @argv) = @_;
    my $io = path(tempdir(CLEANUP => 1));
    my ($in, $out, $err) = map { $io->child($_)->stringify } qw( in out err );
    path($in)->spew('');
    my $pid = fork // die "fork: $!";
    unless ($pid) {
        eval q{ END { close STDOUT; close STDERR; POSIX::_exit($?) } 1 } or POSIX::_exit(96);
        my $code = eval {
            chdir $dir or die "chdir: $!";
            local $ENV{HOME} = "$dir";
            open STDIN,  '<', $in  or die "stdin: $!";
            open STDOUT, '>', $out or die "stdout: $!";
            open STDERR, '>', $err or die "stderr: $!";
            alarm 120;
            $setup->() if $setup;
            @ARGV = @argv;
            OCP->run_cli;
        } // 97;
        exit $code;
    }
    waitpid $pid, 0;
    return {
        exit   => $? >> 8,
        signal => $? & 127,
        out    => path($out)->slurp_utf8,
        err    => path($err)->slurp_utf8,
    };
}

# Every leaf command OCP dispatches to, with the words that reach it: the
# command map's keys, level by level, the way t/383 walks it.
sub leaf_commands {
    my (%words, @leaves);
    my $root = OCP::_command_map('OCP');
    my @todo = map { [ [$_], $root->{$_} ] } sort keys %$root;
    while (my $item = shift @todo) {
        my ($words, $class) = @$item;
        next if $words{$class};
        $words{$class} = $words;
        use_module($class);
        my $map = OCP::_command_map($class);
        if (%$map) { push @todo, map { [ [ @$words, $_ ], $map->{$_} ] } sort keys %$map }
        else       { push @leaves, $class }
    }
    return map { [ $_, $words{$_} ] } sort @leaves;
}

# A dummy for each required option, by its format: a number for i and f, k=v
# for a hash, a word for the rest, nothing for a flag.
sub required_options {
    my ($class) = @_;
    my %data = $class->_options_data;
    my @argv;
    for my $name (sort grep { $data{$_}{required} } keys %data) {
        my $format = $data{$name}{format};
        push @argv, "--$name",
            !defined $format    ? ()
          : $format =~ /%/      ? 'k=v'
          : $format =~ /\A[if]/ ? 1
          :                       'x';
    }
    return @argv;
}

1;
