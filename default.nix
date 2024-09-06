{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorHash = "sha256-OZHOwif4d5zs+lS2j6/Y66c5PThxvJQJiR6bDalLVQ8=";

  subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
