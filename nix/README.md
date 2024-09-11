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
