{
  lib,
  pkgs,
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

    services = {
      openssh = {
        enable = true;
        # https://man.openbsd.org/sshd_config
        # https://www.mankier.com/5/sshd_config
        extraConfig = ''
          AuthorizedKeysCommand ${lib.meta.getExe pkgs.amazon-ec2-ssh-utils.packages.amazon-ec2-ssh-utils} openssh-authorized-keys -f %f -u %u --source ec2-instance-connect --source ec2-key-pairs
        '';
      };
    };
  };
}
