{
  description = "WPA2 Decrypter & Packet Analyzer";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11"; };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            python311
            python311Packages.grpcio
            python311Packages.grpcio-tools
            protobuf
          ];
        };
      };
    };
}
