requires 'Moo';
requires 'MooX::Cmd';
requires 'MooX::Options';
requires 'MooX::Singleton';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
requires 'WWW::Hetzner';
requires 'Crypt::Age';
requires 'File::SOPS', '0.002';
requires 'Rex';
requires 'Net::SSH2';
requires 'IPC::Run';
requires 'IPC::Shareable';
requires 'JSON::MaybeXS';
requires 'File::ShareDir::ProjectDistDir';
requires 'Try::Tiny';
requires 'Types::Standard';
requires 'Term::ANSIColor';
requires 'Term::ReadKey';
requires 'CryptX';
requires 'Crypt::PBKDF2';

# TUI
requires 'Tickit';
requires 'Tickit::Widgets';

# Robocop controller
requires 'IO::Async';
requires 'IO::K8s', '1.002';
requires 'Kubernetes::REST', '1.002';
requires 'Net::Async::Kubernetes';

on test => sub {
    requires 'Test::More';
    requires 'File::Temp';
};
