{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  #vendorSha256 = "sha256-nMnqSXgLJW+pAsV7E7njCqJfcyCaZoRpyXD5Wwck+WQ=";
  vendorSha256 = "";

  subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
