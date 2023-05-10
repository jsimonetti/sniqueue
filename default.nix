{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorSha256 = "sha256-ufbmWA9BWTa32h9s9veBOYTKSjICUmT0s5aWtIPopNs=";

  subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
