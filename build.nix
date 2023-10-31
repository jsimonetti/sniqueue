{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
, lib
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorSha256 = lib.fakeSha256

    subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
