requires 'Moo';
requires 'MooX::Cmd';
requires 'MooX::Options';
requires 'YAML::XS';
requires 'Path::Tiny';
requires 'namespace::clean';
requires 'WWW::Hetzner';
requires 'Crypt::Age';
requires 'File::SOPS';
requires 'Rex';
requires 'Net::SSH2';
requires 'IPC::Run';
requires 'IPC::Shareable';
requires 'JSON::MaybeXS';
requires 'File::ShareDir::ProjectDistDir';
requires 'Try::Tiny';
requires 'Types::Standard';

# Robocop controller
requires 'IO::Async';
requires 'IO::K8s';
requires 'Net::Async::Kubernetes';

on test => sub {
    requires 'Test::More';
    requires 'File::Temp';
};
