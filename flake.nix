{
  description = "WPA2 Decrypter & Packet Analyzer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in with pkgs; rec {
        # Development shell
        devShell = mkShell {
          name = "yarilo-backend";
          nativeBuildInputs = [ doxygen clang-tools gdb cmake ninja spdlog grpc libtins protobuf openssl libpcap aircrack-ng iw libnl ];
        };

        # Runtime package
        packages.Yarilo = pkgs.callPackage ./backend { };

        # Default package
        defaultPackage = packages.Yarilo;
      }
    );
}

