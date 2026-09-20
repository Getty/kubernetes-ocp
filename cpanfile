# Untergrenze, nicht der Auslieferungs-Pin: das Image faehrt 5.42.3 (Dockerfile,
# Makefile:snapshot). Der Floor sagt nur, ab welchem Perl OCP ueberhaupt laeuft,
# und muss deshalb das Perl der Entwicklungsmaschine einschliessen -- sonst
# liegen `make test-host` und `dzil build` dort unter der eigenen Baseline
# (@Author::GETTY traegt den Floor via Prereqs::FromCPANfile als
# MIN_PERL_VERSION ins META). ADR 0025 + Amendment 2026-08-17.
requires 'perl', '5.040001';
requires 'Moo';
# Both are pinned because OCP.pm reaches into their PRIVATE API to check a
# command word before MooX::Cmd sees the argument vector: _build_command_commands
# for the subcommands a class dispatches to, _options_data for which options
# swallow the next argument. Unversioned, that check silently degrades — a
# renamed private method makes _command_map return {} and _command_word_index
# mistake an option's value for a command word, which is how `ocp typo apply`
# used to run apply. These are the versions in cpanfile.snapshot, i.e. the ones
# the image is built from.
requires 'MooX::Cmd', '1.000';
requires 'MooX::Options', '4.103';
requires 'MooX::Singleton';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
# 0.100, not 0.101: 0.101 exists only in that distribution's working tree and
# carries no code change -- its diff against 0.100 is $VERSION lines and
# nothing else. A floor states what OCP needs, not what happens to be
# installed on the machine that last touched this file; a host carrying 0.101
# satisfies 0.100 anyway.
requires 'WWW::Hetzner', '0.100';
# WWW::Hetzner reaches api.hetzner.cloud through LWP::UserAgent, and LWP only
# speaks https once this protocol handler is installed. It used to be cpanm'd
# into the system perl by the Dockerfile, which made the one module standing
# between OCP and every Hetzner API call the one module the snapshot did not
# describe.
requires 'LWP::Protocol::https';
# 0.004, not 0.003: 0.004 caps the recipient-stanza count in an age header
# (CVE-2026-85783) -- every stanza costs an X25519 scalar multiplication before
# the header authenticates, and 0.003 has no cap. 0.004 is now released on CPAN.
# OCP's own
# Crypt::Age->decrypt calls read single-recipient material it wrote itself, so
# the 128-stanza default is never reached and no explicit max_stanzas is
# needed; the third-party decrypt surface is inside File::SOPS, fixed on its
# own board.
requires 'Crypt::Age', '0.004';
# 0.004, not 0.003: 0.004 writes the sops:lastmodified metadata as a quoted
# scalar (0.003 emitted it bare, which sops rejects -- k153; OCP also normalizes
# it on write for files older tools produced). Now released on CPAN.
requires 'File::SOPS', '0.004';
requires 'Rex';
requires 'Rex::Interface::Connection::LibSSH', '0.002';
requires 'IPC::Run';
requires 'JSON::MaybeXS';
requires 'File::ShareDir';
requires 'Try::Tiny';
requires 'Term::ANSIColor';
requires 'Term::ReadKey';
# 0.088 fixed CVE-2026-41564 and 0.089 carried hardening fixes across the
# Digest/Mac/AuthEnc/PK/PRNG surface; 0.091 fixes non-NUL-terminated PVs
# (CryptX #125). The snapshot sat on 0.087, below all of them.
requires 'CryptX', '0.091';
requires 'Crypt::PBKDF2';

# Robocop controller
requires 'IO::Async';
# 1.107 is the first Kubernetes::REST with a native patch_status(); OCP::K8s
# calls it in that version's argument form (Kind first, payload under 'patch').
# It requires IO::K8s 1.107 itself, so the two move together.
requires 'IO::K8s', '1.108';
requires 'Kubernetes::REST', '1.108';
requires 'Net::Async::Kubernetes', '0.008';

on test => sub {
    requires 'Test::More';
    requires 'File::Temp';
};
