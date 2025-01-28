{ pkgs, lib }:

pkgs.buildNpmPackage {
  name = "YariloFrontend";
  version = "0.11.2";
  buildInputs = with pkgs; [ nodejs_18 ];
  src = ./.;

  npmDepsHash = "sha256-pz/5YMgXE4bbLPdZwQV1jFyxQGxYBHDGbGMbKARRfY8=";
  npmBuild = "npm run build";

  installPhase = ''
    mkdir -p $out/src $out/bin
    cp -r build $out/src
    cp package.json $out/src

    echo "#!/usr/bin/env sh" >> $out/bin/yarilo-frontend
    echo "cd $out/src && ${pkgs.nodejs_18}/bin/node build" >> $out/bin/yarilo-frontend
    chmod +x $out/bin/yarilo-frontend
  '';

  meta = {
    description = "WPA2 Decrypter & Packet Analyzer";
    homepage = "https://github.com/TypicalAM/Yarilo";
    license = lib.licenses.gpl3Plus;
    maintainers = with lib.maintainers; [ TypicalAM ];
  };
}
