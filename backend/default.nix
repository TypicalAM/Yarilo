{ pkgs, lib }:

pkgs.stdenv.mkDerivation {
  pname = "Yarilo";
  version = "0.9.3";
  allSrc = ../.;
  src = ./.;

  nativeBuildInputs = with pkgs; [ doxygen clang-tools gdb cmake ninja pkg-config spdlog grpc libtins protobuf openssl libpcap aircrack-ng iw libnl sqlite doxygen ];

  cmakeFlags = [ "-DYARILO_BUILD_DOCS=ON" ];
  patchPhase = ''
    cp $allSrc/protos/service.proto .
    sed -i 's|get_filename_component(hw_proto "..\/protos\/service.proto" ABSOLUTE)|get_filename_component(hw_proto "service.proto" ABSOLUTE)|g' CMakeLists.txt
    sed -i '/\/usr\/local\/include\/libnl3/a ${pkgs.libnl.dev}\/include\/libnl3' cmake/FindLibNL.cmake
  '';
  installPhase = ''
    mkdir -p $out/bin $out/share/doc/yarilo
    mv $TMP/backend/build/yarilo $out/bin
    mv $TMP/backend/build/doc_doxygen/html/* $out/share/doc/yarilo
  '';

  meta = {
    description = "WPA2 Decrypter & Packet Analyzer";
    homepage = "https://github.com/TypicalAM/Yarilo";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ TypicalAM ];
  };
}
