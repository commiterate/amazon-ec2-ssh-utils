{
  inputs,
}:
inputs.system-manager.lib.makeSystemConfig {
  modules = [
    inputs.self.nixosModules.test
    (
      {
        ...
      }:
      {
        config = {
          nixpkgs = {
            hostPlatform = "x86_64-linux";
          };
        };
      }
    )
  ];
}
