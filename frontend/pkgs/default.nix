# Custom packages, we need a custom protobuf version because protoc-gen-js refuses to compile

{ pkgs }: {
  protoc-gen-js = pkgs.callPackage ./protoc-gen-js {
    protobuf = pkgs.callPackage ./protobuf {
      version = "3.13";
      sha256 = "sha256-u/1Yb8+mnDzc3OwirpGESuhjkuKPgqDAvlgo3uuzbbk=";
    };
  };
}
