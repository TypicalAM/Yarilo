{ pkgs, lib }:

pkgs.buildNpmPackage {
  name = "YariloFrontend";
  version = "0.9.6";
  buildInputs = with pkgs; [ nodejs_18 ];
  src = ./.;

  npmDepsHash = "sha256-hoRyv2XmN8myCUPk52Jbw3DzQ/kNAPVuTrTxb+MDVlQ=";
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
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ TypicalAM ];
  };
}
