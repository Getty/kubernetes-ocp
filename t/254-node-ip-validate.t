#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Socket ();

use OCP::Choices;

#
# k254: a node-ip -- the address a node registers by -- arrives from three
# places (`ocp node add --node_ip`, ocp.yaml control_planes[].node_ip, an
# OCPNode's spec.nodeIP) and is checked by ONE function,
# OCP::Choices::node_ip_error: undef when there is nothing to refuse, else
# one line naming the part at fault and what would have worked.
#
# Claims asserted here:
#
#   1. Every form the card accepts passes: one IPv4 or IPv6 literal, or one of
#      each joined by a comma, either order.
#   2. Every rejection has its own line, and the line is specific enough that
#      dropping that one rule changes the answer -- each case below falls
#      through to ANOTHER message (or to undef) when its rule is gone.
#   3. Every line is one line, names the offending part, and carries no
#      field name (the caller prefixes its own: "--node_ip: ").
#   4. Nothing passes that Rex::Rancher, which takes the value on as written,
#      would refuse. Its preflight (Rex::Rancher::Options::check_node_addresses,
#      rex-rancher k100) splits on the comma WITHOUT trimming and puts each
#      part through inet_pton -- which is why whitespace around the comma is
#      refused here instead of trimmed.
#

sub node_ip_error { OCP::Choices::node_ip_error(@_) }

my $FORMS = qr/expected an IPv4 or IPv6 address, or one of each joined by a comma, like 10\.0\.0\.1,fd00::1\z/;
my $KUBELET = qr/, which kubelet refuses as a node-ip; expected an address the other nodes reach this one by\z/;
my $DUAL = qr/; dual-stack takes one IPv4 and one IPv6 address\z/;

# Edges sit next to each refused range on purpose: 126.x and 128.x around
# loopback, 169.253/169.255 around link-local, 223.x/240.x around multicast,
# fe7f/fec0 around fe80::/10. A range drawn one step too wide fails here.
my @ACCEPTED = (
    '10.230.30.50',
    '192.168.0.165',
    '126.255.255.255',
    '128.0.0.1',
    '169.253.255.255',
    '169.255.0.1',
    '223.255.255.255',
    '240.0.0.1',
    '0.0.0.1',
    'fd00::5',
    '2001:db8::1',
    'FD00::5',
    '64:ff9b::a00:1',
    'fe7f::1',
    'fec0::1',
    '::2',
    '10.230.30.50,fd00::5',
    'fd00::5,10.230.30.50',
);

subtest 'every accepted form passes' => sub {
    is node_ip_error($_), undef, "'$_' passes" for @ACCEPTED;
};

subtest 'undef is nothing to refuse: the node-ip is left out' => sub {
    is node_ip_error(undef), undef, 'undef -> undef';
};

# [ value, the part the line has to quote (undef: none), pattern ]
my @REJECTED = (
    # not a string
    [ [ '10.0.0.1' ],   undef, qr/\Amust be one string like 10\.0\.0\.1 or 10\.0\.0\.1,fd00::1, not a list\z/ ],
    [ { a => 1 },       undef, qr/\Amust be one string .*, not a mapping\z/ ],
    [ \'10.0.0.1',      undef, qr/\Amust be one string .*, not a reference\z/ ],

    # empty
    [ '',               undef, qr/\Amust not be empty; $FORMS/ ],
    [ '   ',            undef, qr/\Amust not be empty; $FORMS/ ],

    # whitespace: refused, never trimmed; the fix is named when it is one
    [ '10.0.0.1, fd00::1',  '10.0.0.1, fd00::1',  qr/ contains whitespace: write '10\.0\.0\.1,fd00::1'\z/ ],
    [ '10.0.0.1 ,fd00::1',  '10.0.0.1 ,fd00::1',  qr/ contains whitespace: write '10\.0\.0\.1,fd00::1'\z/ ],
    [ ' 10.0.0.1',          ' 10.0.0.1',          qr/ contains whitespace: write '10\.0\.0\.1'\z/ ],
    [ "10.0.0.1\t",         '10.0.0.1\x{9}',      qr/ contains whitespace: write '10\.0\.0\.1'\z/ ],
    [ "10.0.0.1\n",         '10.0.0.1\x{a}',      qr/ contains whitespace: write '10\.0\.0\.1'\z/ ],
    # ... and not named when it would be refused too (a hint only where true)
    [ 'syn apse',           'syn apse',           qr/'syn apse' contains whitespace; $FORMS/ ],
    [ '127.0.0.1 ',         '127.0.0.1 ',         qr/ contains whitespace; $FORMS/ ],

    # empty parts, before the count
    [ '10.0.0.1,',          '10.0.0.1,',          qr/ has an empty address next to a comma; $FORMS/ ],
    [ ',fd00::1',           ',fd00::1',           qr/ has an empty address next to a comma; $FORMS/ ],
    [ ',',                  ',',                  qr/ has an empty address next to a comma; $FORMS/ ],
    [ '10.0.0.1,,fd00::1',  '10.0.0.1,,fd00::1',  qr/ has an empty address next to a comma; $FORMS/ ],

    # more than two
    [ '10.0.0.1,fd00::1,10.0.0.2',       '10.0.0.1,fd00::1,10.0.0.2',       qr/ lists 3 addresses; $FORMS/ ],
    [ '1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4', '1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4', qr/ lists 4 addresses; $FORMS/ ],

    # hostnames and other non-literals
    [ 'synapse',               'synapse',               qr/ is not an IP address \(hostnames are not resolved\); $FORMS/ ],
    [ 'synapse.ai.citilan.de', 'synapse.ai.citilan.de', qr/ is not an IP address \(hostnames are not resolved\); $FORMS/ ],
    [ 'localhost',             'localhost',             qr/ is not an IP address/ ],
    [ '10.0.0.1,synapse',      'synapse',               qr/\A'synapse' is not an IP address/ ],
    [ '1.2.3',                 '1.2.3',                 qr/ is not an IP address/ ],
    [ '256.0.0.1',             '256.0.0.1',             qr/ is not an IP address/ ],
    [ '010.0.0.1',             '010.0.0.1',             qr/ is not an IP address/ ],
    [ '[fd00::1]',             '[fd00::1]',             qr/ is not an IP address/ ],
    [ 'fe80::1%eno1',          'fe80::1%eno1',          qr/ is not an IP address/ ],
    # inet_pton reads a C string: without the character check this passes
    [ "10.0.0.1\0x",           '10.0.0.1\x{0}x',        qr/ is not an IP address/ ],
    [ 'synapse/24',            'synapse/24',            qr/ is not an IP address/ ],

    # CIDR
    [ '10.230.30.50/24',    '10.230.30.50/24', qr/ is a network \(CIDR\), not an address: write the node's own address, without \/24\z/ ],
    [ 'fd00::5/64',         'fd00::5/64',      qr/ is a network \(CIDR\), not an address: .* without \/64\z/ ],
    [ '10.0.0.1,fd00::/64', 'fd00::/64',       qr/\A'fd00::\/64' is a network \(CIDR\)/ ],

    # what kubelet refuses as a node IP
    [ '127.0.0.1',          '127.0.0.1',       qr/ is a loopback address$KUBELET/ ],
    [ '127.255.255.254',    '127.255.255.254', qr/ is a loopback address$KUBELET/ ],
    [ '::1',                '::1',             qr/ is a loopback address$KUBELET/ ],
    [ '10.0.0.1,::1',       '::1',             qr/\A'::1' is a loopback address/ ],
    [ '0.0.0.0',            '0.0.0.0',         qr/ is the unspecified address$KUBELET/ ],
    [ '::',                 '::',              qr/ is the unspecified address$KUBELET/ ],
    [ '0:0:0:0:0:0:0:0',    '0:0:0:0:0:0:0:0', qr/ is the unspecified address$KUBELET/ ],
    [ '169.254.0.1',        '169.254.0.1',     qr/ is a link-local address$KUBELET/ ],
    [ '169.254.255.255',    '169.254.255.255', qr/ is a link-local address$KUBELET/ ],
    [ 'fe80::1',            'fe80::1',         qr/ is a link-local address$KUBELET/ ],
    [ 'febf:ffff::1',       'febf:ffff::1',    qr/ is a link-local address$KUBELET/ ],
    [ '224.0.0.1',          '224.0.0.1',       qr/ is a multicast address$KUBELET/ ],
    [ '239.255.255.255',    '239.255.255.255', qr/ is a multicast address$KUBELET/ ],
    [ 'ff02::1',            'ff02::1',         qr/ is a multicast address$KUBELET/ ],
    [ 'ff00::',             'ff00::',          qr/ is a multicast address$KUBELET/ ],

    # IPv4-mapped IPv6: kubelet counts it as IPv4, so it is named in that form
    [ '::ffff:10.0.0.1',          '::ffff:10.0.0.1',  qr/ is an IPv4 address written as IPv6: write 10\.0\.0\.1\z/ ],
    [ '10.0.0.2,::ffff:10.0.0.1', '::ffff:10.0.0.1',  qr/\A'::ffff:10\.0\.0\.1' is an IPv4 address written as IPv6/ ],
    # ... unless that form is refused too (a hint only where true)
    [ '::ffff:127.0.0.1',         '::ffff:127.0.0.1', qr/ is a loopback address$KUBELET/ ],

    # dual-stack: the same address twice, two of one family
    [ '10.0.0.1,10.0.0.1',   '10.0.0.1,10.0.0.1',   qr/ names the same address twice$DUAL/ ],
    [ 'fd00::1,fd00:0:0::1', 'fd00::1,fd00:0:0::1', qr/ names the same address twice$DUAL/ ],
    [ '10.0.0.1,10.0.0.2',   '10.0.0.1,10.0.0.2',   qr/ holds two IPv4 addresses$DUAL/ ],
    [ 'fd00::1,fd00::2',     'fd00::1,fd00::2',     qr/ holds two IPv6 addresses$DUAL/ ],
);

sub shown {
    my ($v) = @_;
    return ref $v ? ref($v) . ' ref' : "'" . ($v =~ s/([^\x20-\x7e])/sprintf('\\x{%x}', ord $1)/ger) . "'";
}

subtest 'every rejection: its own line, naming the part at fault' => sub {
    for my $case (@REJECTED) {
        my ($value, $part, $want) = @$case;
        my $err = node_ip_error($value);
        my $label = shown($value);

        ok defined $err, "$label is refused" or next;
        like $err, $want, "$label: $err";
        unlike $err, qr/\n/, "$label: one line";
        unlike $err, qr/\A-*node_ip/, "$label: no field name, the caller prefixes its own";
        ok index($err, "'" . $part . "'") >= 0, "$label: names '$part'"
            if defined $part;
    }
};

# The lib's rule as rex-rancher k100 states it, for when the lib itself is not
# installed (the image carries a Rex::Rancher without it): split on the comma
# as is, every part an inet_pton literal.
sub rex_rancher_takes {
    my ($value) = @_;
    my @ip = split /,/, $value, -1;
    return 0 unless @ip;
    for my $ip (@ip) {
        return 0 unless defined Socket::inet_pton(Socket::AF_INET(), $ip)
                     || defined Socket::inet_pton(Socket::AF_INET6(), $ip);
    }
    return 1;
}

my @PLAIN = grep { !ref } @ACCEPTED, map { $_->[0] } @REJECTED;

subtest 'nothing passes that Rex::Rancher would refuse' => sub {
    for my $value (@PLAIN) {
        next if defined node_ip_error($value);
        ok rex_rancher_takes($value), "'$value' passes here, and the lib's split + inet_pton take it";
    }
    ok !rex_rancher_takes('10.0.0.1, fd00::1'),
        'the lib refuses whitespace around the comma -- the reason it is refused here, not trimmed';
};

subtest 'against Rex::Rancher itself, when it carries the check' => sub {
    my $can = eval { require Rex::Rancher::Options; Rex::Rancher::Options->can('check_node_addresses') };
    plan skip_all => 'Rex::Rancher::Options->check_node_addresses not installed (rex-rancher k100)'
        unless $can;

    for my $value (@PLAIN) {
        next if defined node_ip_error($value);
        ok eval { Rex::Rancher::Options->check_node_addresses(node_ip => $value); 1 },
            "'$value' passes here and in Rex::Rancher";
    }
    ok !eval { Rex::Rancher::Options->check_node_addresses(node_ip => '10.0.0.1, fd00::1'); 1 },
        'Rex::Rancher refuses whitespace around the comma';
};

done_testing;
