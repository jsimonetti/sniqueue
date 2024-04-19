{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorHash = "sha256-CWTylM9WqUtlr/pIdWXBCch+4R2iaWDghODJjk0N7lg=";

  subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
