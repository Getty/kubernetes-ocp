package OCP::Kubeconfig;
# ABSTRACT: Rename and merge kubeconfig entries

use strict;
use warnings;
use Path::Tiny qw(path);

use OCP;

our $VERSION = '0.001';

# Named entry lists in a kubeconfig, and the key holding their payload.
my %SECTIONS = (
    clusters => 'cluster',
    users    => 'user',
    contexts => 'context',
);

sub parse {
    my ($class, $yaml) = @_;

    my $struct = eval { OCP->load($yaml) };
    die "Not a valid kubeconfig: $@" if $@;
    die "Not a valid kubeconfig: expected a YAML mapping\n"
        unless ref $struct eq 'HASH';

    return $struct;
}

# Rename clusters/users/contexts to the OCP cluster name so a merge into a
# shared kubeconfig cannot clobber unrelated entries. RKE2 and K3s both ship
# everything named 'default', which would collide with every other cluster.
#
# Returns the new current-context name.
sub rename_entries {
    my ($class, $kc, $name) = @_;

    die "rename_entries: name required\n" unless defined $name && length $name;

    my %map;
    for my $section (qw(clusters users)) {
        my $entries = $kc->{$section} || [];
        for my $entry (@$entries) {
            my $old = $entry->{name} // '';
            my $new = @$entries == 1 ? $name : "$name-$old";
            $map{$section}{$old} = $new;
            $entry->{name} = $new;
        }
    }

    my $contexts = $kc->{contexts} || [];
    my $current;
    for my $ctx (@$contexts) {
        my $old = $ctx->{name} // '';
        $ctx->{name} = @$contexts == 1 ? $name : "$name-$old";
        $current //= $ctx->{name};

        my $body = $ctx->{context} || {};
        for my $ref (['cluster', 'clusters'], ['user', 'users']) {
            my ($field, $section) = @$ref;
            my $old_ref = $body->{$field} // '';
            $body->{$field} = $map{$section}{$old_ref}
                if exists $map{$section}{$old_ref};
        }
    }

    $kc->{'current-context'} = $current if defined $current;

    return $current;
}

# Merge $incoming into $base. Entries with the same name are replaced in
# place, everything else is kept. current-context follows $incoming.
sub merge {
    my ($class, $base, $incoming) = @_;

    $base     = {} unless ref $base eq 'HASH';
    $incoming = {} unless ref $incoming eq 'HASH';

    my %out = %$base;
    $out{apiVersion} ||= $incoming->{apiVersion} || 'v1';
    $out{kind}       ||= $incoming->{kind}       || 'Config';

    for my $section (sort keys %SECTIONS) {
        my @merged = @{ $out{$section} || [] };

        for my $entry (@{ $incoming->{$section} || [] }) {
            my $name = $entry->{name} // next;
            my ($idx) = grep { ($merged[$_]{name} // '') eq $name } 0 .. $#merged;
            if (defined $idx) {
                $merged[$idx] = $entry;
            } else {
                push @merged, $entry;
            }
        }

        $out{$section} = \@merged;
    }

    $out{'current-context'} = $incoming->{'current-context'}
        if defined $incoming->{'current-context'};

    return \%out;
}

# Where `ocp kubeconfig -e` writes: $KUBECONFIG (first entry) or ~/.kube/config.
sub default_target {
    my ($class) = @_;

    if (defined $ENV{KUBECONFIG} && length $ENV{KUBECONFIG}) {
        my ($first) = split /:/, $ENV{KUBECONFIG};
        return $first if defined $first && length $first;
    }

    my $home = $ENV{HOME} // eval { (getpwuid($<))[7] } // '';
    die "Cannot determine home directory. Use 'ocp kubeconfig -o FILE' instead.\n"
        unless length $home;

    return path($home)->child('.kube', 'config')->stringify;
}

# True when we are inside a container, where $HOME is usually not persistent.
sub in_container {
    my ($class) = @_;

    return 1 if -e '/.dockerenv' || -e '/run/.containerenv';

    my $cgroup = eval { path('/proc/1/cgroup')->slurp } // '';
    return 1 if $cgroup =~ m{(?:docker|containerd|kubepods|podman)};

    return 0;
}

# Merge a kubeconfig into $target (default: default_target), backing up the
# previous file first. Returns a hashref: target, backup, context.
sub export {
    my ($class, %args) = @_;

    my $yaml = $args{kubeconfig};
    die "export: kubeconfig required\n" unless defined $yaml && length $yaml;

    my $name   = $args{name} // 'ocp';
    my $target = path($args{target} // $class->default_target);

    my $incoming = $class->parse($yaml);
    my $context  = $class->rename_entries($incoming, $name);

    my ($base, $backup) = ({}, undef);
    if (-f $target) {
        $base = $class->parse($target->slurp_utf8);
        $backup = path("$target.ocp-bak");
        $target->copy($backup);
    }

    my $merged = $class->merge($base, $incoming);

    $target->parent->mkpath;
    $target->spew_utf8(OCP->dump($merged));
    $target->chmod(0600);

    return {
        target  => "$target",
        backup  => defined $backup ? "$backup" : undef,
        context => $context,
    };
}

1;

__END__

=head1 NAME

OCP::Kubeconfig - Rename and merge kubeconfig entries

=head1 SYNOPSIS

    use OCP::Kubeconfig;

    my $result = OCP::Kubeconfig->export(
        kubeconfig => $decrypted_yaml,
        name       => $config->name,
        # target   => '/path/to/config',   # default: $KUBECONFIG or ~/.kube/config
    );

    print "context $result->{context} merged into $result->{target}\n";

=head1 DESCRIPTION

RKE2 and K3s hand out kubeconfigs whose cluster, user and context are all
named C<default>. Writing one of those straight into a shared
F<~/.kube/config> would overwrite the entries of any other cluster. This
module renames the entries to the OCP cluster name first, then merges them
into the existing file, leaving unrelated entries untouched.

=head1 METHODS

=head2 parse

    my $struct = OCP::Kubeconfig->parse($yaml);

Parses kubeconfig YAML into a hashref. Dies on anything that is not a mapping.

=head2 rename_entries

    my $context = OCP::Kubeconfig->rename_entries($struct, 'mycluster');

Renames clusters, users and contexts in place and rewires the context
references. A single entry takes the name as-is, multiple entries get it as
a prefix. Sets and returns C<current-context>.

=head2 merge

    my $merged = OCP::Kubeconfig->merge($base, $incoming);

Merges named entries, replacing same-named ones and appending the rest.
C<current-context> follows C<$incoming>.

=head2 default_target

    my $path = OCP::Kubeconfig->default_target;

The first path in C<$KUBECONFIG>, or F<~/.kube/config>.

=head2 in_container

    warn "..." if OCP::Kubeconfig->in_container;

True inside Docker/Podman/Kubernetes, where C<$HOME> is usually throwaway.

=head2 export

    my $result = OCP::Kubeconfig->export(kubeconfig => $yaml, name => 'mycluster');

Renames, merges and writes the target file with mode 0600, backing up an
existing file as F<< <target>.ocp-bak >>. Returns a hashref with C<target>,
C<backup> and C<context>.

=cut
