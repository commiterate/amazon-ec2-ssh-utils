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
            hostPlatform = "x86_64-darwin";
          };
        };
      }
    )
  ];
}
