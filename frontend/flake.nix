{
  description = "WPA2 Decrypter & Packet Analyzer";

  inputs = { nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11"; };

  outputs = inputs@{ flake-parts, ... }:
    let
      pkgs = inputs.nixpkgs.legacyPackages.x86_64-linux;
      ownPkgs = import ./pkgs { inherit pkgs; };
    in 
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {
        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.nodejs_20
            pkgs.nodePackages.svelte-language-server
            pkgs.protobuf
            ownPkgs.protoc-gen-js
          ];
        };
      };
    };
}
