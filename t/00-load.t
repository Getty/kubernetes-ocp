#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Core
use_ok('OCP');
use_ok('OCP::Config');
use_ok('OCP::Secrets');
use_ok('OCP::Keys');
use_ok('OCP::SSH');
use_ok('OCP::K3s');
use_ok('OCP::Versions');
use_ok('OCP::Password');

# Roles
use_ok('OCP::Role::Cmd');

# Cmd modules (loaded via MooX::Cmd but also standalone)
use_ok('OCP::Cmd::Apply');
use_ok('OCP::Cmd::Init');
use_ok('OCP::Cmd::Status');
use_ok('OCP::Cmd::Destroy');
use_ok('OCP::Cmd::Kubeconfig');
use_ok('OCP::Cmd::SSH');
use_ok('OCP::Cmd::InjectKey');
use_ok('OCP::Cmd::DeployRobocop');
use_ok('OCP::Cmd::Hetzner');
use_ok('OCP::Cmd::Version');
use_ok('OCP::Cmd::Update');
use_ok('OCP::Cmd::Edit');

# UI
use_ok('OCP::UI');
use_ok('OCP::UI::Form');
use_ok('OCP::UI::Field');
use_ok('OCP::UI::Wizard');

# Hetzner
use_ok('OCP::Hetzner');

# Provider
use_ok('OCP::Provider');
use_ok('OCP::Provider::Hetzner');
use_ok('OCP::Provider::SSH');
use_ok('OCP::Provider::Local');

# Kubernetes helpers
use_ok('OCP::Kubernetes');

done_testing;
