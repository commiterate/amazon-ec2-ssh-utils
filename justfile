#
# just configuration.
#
# https://just.systems/man/en
#

# List recipes.
help:
	just --list

# Build the Nix flake outputs.
nix:
	just nix/release

# Build the client.
client:
	just client/release

# Build the tests.
tests:
	just tests/release

# Build the infrastructure.
infrastructure:
	just infrastructure/release

# Release build.
release: nix client tests infrastructure
