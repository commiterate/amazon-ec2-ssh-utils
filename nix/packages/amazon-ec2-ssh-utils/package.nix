{
  buildGoModule,
  lib,
}:
buildGoModule (finalAttrs: {
  pname = "amazon-ec2-ssh-utils";
  version = "0.0.0";

  src =
    with lib.fileset;
    toSource (
      let
        root = ../../../client;
      in
      {
        inherit root;
        fileset = unions (
          builtins.map (path: root + path) [
            /cmd
            /internal
            /go.mod
            /go.sum
          ]
        );
      }
    );

  # Auto-update with `nix-update --flake --version skip amazon-ec2-ssh-utils`.
  vendorHash = "sha256-GivErbZFhLp9Gi3NywnsaLvkmj2Mzjq9Zrd4NR9nzOE=";

  env = {
    CGO_ENABLED = 0;
  };

  meta = {
    description = "Amazon EC2 SSH utilities";
    license = lib.licenses.mit;
    mainProgram = finalAttrs.pname;
  };
})
