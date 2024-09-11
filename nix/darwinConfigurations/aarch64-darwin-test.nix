{
  inputs,
}:
inputs.nix-darwin.lib.darwinSystem {
  modules = [
    inputs.self.darwinModules.test
    (
      {
        ...
      }:
      {
        config = {
          nixpkgs = {
            hostPlatform = "aarch64-darwin";
          };
        };
      }
    )
  ];
}
