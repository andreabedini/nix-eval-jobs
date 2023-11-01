{ stdenv
, lib
, nix
, pkgs
, srcDir ? null
}:

let
  filterMesonBuild = builtins.filterSource
    (path: type: type != "directory" || baseNameOf path != "build");
in
stdenv.mkDerivation {
  pname = "nix-eval-jobs";
  version = "2.16.0";
  src = if srcDir == null then filterMesonBuild ./. else srcDir;
  buildInputs = with pkgs; [
    nlohmann_json
    nix
    nix.debug
    nix.dev
    boost
  ];
  nativeBuildInputs = with pkgs; [
    bear
    meson
    pkg-config
    ninja
    # nlohmann_json can be only discovered via cmake files
    cmake
  ] ++ (lib.optional stdenv.cc.isClang [ pkgs.bear pkgs.clang-tools ]);

  meta = {
    description = "Hydra's builtin hydra-eval-jobs as a standalone";
    homepage = "https://github.com/nix-community/nix-eval-jobs";
    license = lib.licenses.gpl3;
    maintainers = with lib.maintainers; [ adisbladis mic92 ];
    platforms = lib.platforms.unix;
  };
}
