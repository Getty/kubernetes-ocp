requires 'Moo';
requires 'MooX::Cmd';
requires 'MooX::Options';
requires 'MooX::Singleton';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
requires 'WWW::Hetzner', '0.100';
# WWW::Hetzner reaches api.hetzner.cloud through LWP::UserAgent, and LWP only
# speaks https once this protocol handler is installed. It used to be cpanm'd
# into the system perl by the Dockerfile, which made the one module standing
# between OCP and every Hetzner API call the one module the snapshot did not
# describe.
requires 'LWP::Protocol::https';
requires 'Crypt::Age', '0.001';
requires 'File::SOPS', '0.002';
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
requires 'IO::K8s', '1.107';
requires 'Kubernetes::REST', '1.107';
requires 'Net::Async::Kubernetes', '0.007';

on test => sub {
    requires 'Test::More';
    requires 'File::Temp';
};
