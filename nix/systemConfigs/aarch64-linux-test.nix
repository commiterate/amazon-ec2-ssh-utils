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
            hostPlatform = "aarch64-linux";
          };
        };
      }
    )
  ];
}
