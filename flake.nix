#
# Nix flake.
#
# https://nix.dev/manual/nix/latest/command-ref/new-cli/nix3-flake#flake-format
# https://wiki.nixos.org/wiki/Flakes#Flake_schema
#
{
  inputs = {
    # https://nixos.org/manual/nixpkgs/unstable
    # https://search.nixos.org/packages?channel=unstable
    nixpkgs = {
      type = "github";
      owner = "NixOS";
      repo = "nixpkgs";
      ref = "refs/heads/nixos-unstable";
    };

    # https://github.com/numtide/system-manager
    system-manager = {
      type = "github";
      owner = "numtide";
      repo = "system-manager";
      ref = "refs/heads/main";
      inputs = {
        nixpkgs = {
          follows = "nixpkgs";
        };
      };
    };

    # https://github.com/LnL7/nix-darwin
    nix-darwin = {
      type = "github";
      owner = "LnL7";
      repo = "nix-darwin";
      ref = "refs/heads/master";
      inputs = {
        nixpkgs = {
          follows = "nixpkgs";
        };
      };
    };
  };

  outputs =
    inputs:
    {
      # Nixpkgs overlays.
      #
      # Include dependency overlays with `inputs.nixpkgs.lib.fixedPoints.composeManyExtensions`.
      #
      # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.fixedPoints.composeManyExtensions
      overlays = {
        default =
          final: prev:
          # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.attrsets.recursiveUpdate
          inputs.nixpkgs.lib.attrsets.recursiveUpdate prev (
            # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
            inputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
              inherit (final) callPackage;
              directory = ./nix/overlays/default;
            }
          );

        # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.fixedPoints.composeManyExtensions
        development = inputs.nixpkgs.lib.fixedPoints.composeManyExtensions [
          inputs.self.overlays.default
          (
            final: prev:
            # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.attrsets.recursiveUpdate
            inputs.nixpkgs.lib.attrsets.recursiveUpdate prev (
              # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
              inputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
                inherit (final) callPackage;
                directory = ./nix/overlays/development;
              }
            )
          )
        ];
      };
    }
    // (
      let
        # Override inputs.
        #
        # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.attrsets.recursiveUpdate
        finalInputs = inputs.nixpkgs.lib.attrsets.recursiveUpdate inputs {
          nixpkgs = {
            # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.attrsets.mapAttrs
            legacyPackages = inputs.nixpkgs.lib.attrsets.mapAttrs (
              localSystem: packages:
              # https://github.com/NixOS/nixpkgs/blob/nixos-unstable/pkgs/top-level/default.nix
              import inputs.nixpkgs {
                inherit localSystem;

                overlays = [
                  inputs.self.overlays.development
                ];
              }
            ) inputs.nixpkgs.legacyPackages;
          };

          system-manager = {
            lib = {
              makeSystemConfig =
                args:
                inputs.system-manager.lib.makeSystemConfig (
                  args
                  // {
                    modules = [
                      (_: {
                        # Nix installed by the Determinate Nix installer self-manages.
                        nix = {
                          enable = false;
                        };

                        system-manager = {
                          allowAnyDistro = true;
                        };
                      })
                    ]
                    ++ args.modules;
                    # Add overlays here instead of in modules to avoid infinite recursion.
                    overlays = [
                      inputs.system-manager.overlays.default
                      inputs.self.overlays.development
                    ]
                    ++ (args.overlays or [ ]);
                  }
                );
            };
          };

          nix-darwin = {
            lib = {
              darwinSystem =
                args:
                inputs.nix-darwin.lib.darwinSystem (
                  args
                  // {
                    modules = [
                      (_: {
                        # Nix installed by the Determinate Nix installer self-manages.
                        nix = {
                          enable = false;
                        };

                        nixpkgs = {
                          overlays = [
                            inputs.nix-darwin.overlays.default
                            inputs.self.overlays.test
                          ];
                        };
                      })
                    ]
                    ++ args.modules;
                  }
                );
            };
          };
        };

        # Output systems.
        #
        # https://github.com/NixOS/nixpkgs/blob/nixos-unstable/lib/systems/flake-systems.nix
        systems = [
          "aarch64-darwin"
          "aarch64-linux"
          "x86_64-linux"
        ];

        # Return an attribute set of system to the result of applying `f`.
        #
        # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.attrsets.genAttrs
        genSystemAttrs = f: finalInputs.nixpkgs.lib.attrsets.genAttrs systems f;
      in
      {
        # NixOS modules.
        #
        # For NixOS + system-manager configurations.
        nixosModules =
          # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
          finalInputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
            callPackage = file: args: import file;
            directory = ./nix/nixosModules;
          };

        # nix-darwin modules.
        #
        # For nix-darwin configurations.
        darwinModules =
          # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
          finalInputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
            callPackage = file: args: import file;
            directory = ./nix/darwinModules;
          };

        # system-manager configurations.
        #
        # For `system-manager {register/pre-populate/switch} --flake` on non-NixOS Linux systems.
        systemConfigs =
          # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
          finalInputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
            # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.customisation.callPackageWith
            callPackage = finalInputs.nixpkgs.lib.customisation.callPackageWith { inputs = finalInputs; };
            directory = ./nix/systemConfigs;
          };

        # nix-darwin configurations.
        #
        # For `darwin-rebuild switch --flake` on macOS systems.
        darwinConfigurations =
          # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.filesystem.packagesFromDirectoryRecursive
          finalInputs.nixpkgs.lib.filesystem.packagesFromDirectoryRecursive {
            # https://nixos.org/manual/nixpkgs/unstable#function-library-lib.customisation.callPackageWith
            callPackage = finalInputs.nixpkgs.lib.customisation.callPackageWith { inputs = finalInputs; };
            directory = ./nix/darwinConfigurations;
          };

        # Packages.
        #
        # For `nix build`.
        packages = genSystemAttrs (
          system: finalInputs.nixpkgs.legacyPackages.${system}.amazon-ec2-ssh-utils.packages
        );

        # Development shells.
        #
        # For `nix develop` and direnv's `use flake`.
        devShells = genSystemAttrs (
          system: finalInputs.nixpkgs.legacyPackages.${system}.amazon-ec2-ssh-utils.devShells
        );
      }
    );
}
