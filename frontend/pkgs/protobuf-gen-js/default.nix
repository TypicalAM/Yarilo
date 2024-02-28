{ stdenv, lib, fetchFromGitHub, protobuf, pkg-config }:

stdenv.mkDerivation rec {
  pname = "protobuf-gen-js";
  version = "3.21.2";

  src = fetchFromGitHub {
    owner = "protocolbuffers";
    repo = "protobuf-javascript";
    rev = "v${version}";
    sha256 = "sha256:19gk0fx73a907x55ji7rq9r1n7qc7x1m1yy2r3xk0malzg2zlqsf";
  };

  protobufSrc = protobuf.src;

  buildInputs = [ protobuf ];
  nativeBuildInputs = [ pkg-config ];

  # I refuse to write this myself, for now, hehehe
  # I refuse to use bazel to build this, for now, because bazel+nix==:(

  buildPhase = ''
    runHook preBuild

    g++ \
      -o protoc-gen-js \
      \
      -I. \
      $(pkg-config --cflags protobuf) \
      -I$protobufSrc/src \
      \
      $(pkg-config --libs protobuf) \
      -lprotoc \
      generator/*.cc

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    install -D -m755 protoc-gen-js $out/bin/protoc-gen-js

    runHook postInstall
  '';

  meta = with lib; {
    description = "Protobuf plugin for generating Javascript code";
    homepage = "https://github.com/protocolbuffers/protobuf-javascript";
    license = licenses.bsd3;
    maintainers = with maintainers; [ lukegb ];
  };
}
