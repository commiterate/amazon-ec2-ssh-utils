{
  lib,
  pkgs,
  utils,
  ...
}:
{
  config = {
    environment = {
      systemPackages = with pkgs.amazon-ec2-ssh-utils.packages; [
        amazon-ec2-ssh-utils
        amazon-ec2-ssh-utils-tests
      ];
    };

    systemd = {
      services = {
        # OpenSSH doesn't provide systemd configurations. Refer to other Linux distributions.
        #
        # https://gitlab.archlinux.org/archlinux/packaging/packages/openssh
        # https://salsa.debian.org/ssh-team/openssh
        sshd-keygen = {
          # → 📍
          after = [ ];
          #   📍 →
          before = [ ];
          # ⚙️
          serviceConfig = {
            Type = "oneshot";
            ExecStart = utils.escapeSystemdExecArgs [
              # https://man.openbsd.org/ssh-keygen
              # https://www.mankier.com/1/ssh-keygen
              (lib.meta.getExe' pkgs.openssh "ssh-keygen")
              "-A"
            ];
          };
        };

        # OpenSSH doesn't provide systemd configurations. Refer to other Linux distributions.
        #
        # https://gitlab.archlinux.org/archlinux/packaging/packages/openssh
        # https://salsa.debian.org/ssh-team/openssh
        sshd = {
          # → 📍
          after = [
            "network.target"
            "nss-user-lookup.target"
            "sshd-keygen.service"
          ];
          wants = [ "sshd-keygen.service" ];
          #   📍 →
          before = [ ];
          wantedBy = [ "multi-user.target" ];
          # ⚙️
          serviceConfig = {
            Type = "notify";
            ExecStart = utils.escapeSystemdExecArgs [
              # https://man.openbsd.org/sshd
              # https://www.mankier.com/8/sshd
              (lib.meta.getExe' pkgs.openssh "sshd")
              "-D"
              "-f"
              # https://man.openbsd.org/sshd_config
              # https://www.mankier.com/5/sshd_config
              (pkgs.writeText "sshd_config" ''
                AuthorizedKeysCommand ${lib.meta.getExe pkgs.amazon-ec2-ssh-utils.packages.amazon-ec2-ssh-utils} openssh-authorized-keys -f %f -u %u --source ec2-instance-connect --source ec2-key-pairs
                AuthorizedKeysCommandUser nobody
              '')
            ];
            KillMode = "process";
            Restart = "always";
          };
        };
      };
    };
  };
}
