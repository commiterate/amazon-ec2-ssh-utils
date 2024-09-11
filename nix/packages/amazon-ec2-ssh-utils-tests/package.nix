{
  buildGoModule,
  lib,
}:
buildGoModule (finalAttrs: {
  pname = "amazon-ec2-ssh-utils-tests";
  version = "0.0.0";

  src =
    with lib.fileset;
    toSource (
      let
        root = ../../../tests;
      in
      {
        inherit root;
        fileset = unions (
          builtins.map (path: root + path) [
            /internal
            /go.mod
            /go.sum
          ]
        );
      }
    );

  # Auto-update with `nix-update --flake --version skip amazon-ec2-ssh-utils-tests`.
  vendorHash = "sha256-V5pD7nHZ6N4d0IRuKAArtJFwdQgUSYk5R2CGY5z/1do=";

  env = {
    CGO_ENABLED = 0;
  };

  buildPhase = ''
    go test -c -o ${builtins.placeholder "out"}/bin/${finalAttrs.pname} ./internal/...
  '';

  doCheck = false;

  meta = {
    description = "Amazon EC2 SSH utilities tests";
    license = lib.licenses.mit;
    mainProgram = finalAttrs.pname;
  };
})
