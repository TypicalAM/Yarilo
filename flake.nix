{
  description = "WPA2 Decrypter & Packet Analyzer";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; };
      in with pkgs; rec {
        # Development shell
        devShell = mkShell {
          name = "yarilo";
          nativeBuildInputs = [ doxygen clang-tools gdb cmake ninja spdlog grpc libtins protobuf openssl libpcap aircrack-ng iw libnl nodejs protobuf sqlite go ];
        };

        # Runtime package
        packages.yarilo = pkgs.callPackage ./backend { };
        packages.yarilo-battery = (pkgs.callPackage ./backend { }).overrideAttrs (oldAttrs: rec {
          cmakeFlags = oldAttrs.cmakeFlags or [ ] ++ [ "-DYARILO_BATTERY_SUPPORT=ON" ];
        });
        packages.yarilo-frontend = pkgs.callPackage ./frontend { };

        # Default package
        defaultPackage = packages.yarilo;
      }
    );
}
