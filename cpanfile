requires 'Moo';
requires 'MooX::Cmd';
requires 'MooX::Options';
requires 'MooX::Singleton';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
requires 'WWW::Hetzner', '0.100';
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
requires 'CryptX';
requires 'Crypt::PBKDF2';

# Robocop controller
requires 'IO::Async';
requires 'IO::K8s', '1.105';
requires 'Kubernetes::REST', '1.106';
requires 'Net::Async::Kubernetes', '0.007';

on test => sub {
    requires 'Test::More';
    requires 'File::Temp';
};
