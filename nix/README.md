# Nix

Nix flake outputs.

## Layout

```text
Key:
🤖 = Generated

.
│   # Packages.
├── packages
│   └── {package}
│       ├── package.nix
│       └── {package support file (e.g. patch)}
│
│   # Development shells.
├── devShells
│   └── {shell}.nix
│
│   # NixOS modules.
├── nixosModules
│   └── {module}.nix
│
│   # nix-darwin modules.
├── darwinModules
│   └── {module}.nix
│
│   # system-manager configurations.
├── systemConfigs
│   └── {configuration}.nix
│
│   # nix-darwin configurations.
└── darwinConfigurations
    └── {configuration}.nix
```

## Developing

Common build recipes are provided as Just recipes. To list them, run:

```shell
just help
```

To build the project, run:

```shell
just release
```
