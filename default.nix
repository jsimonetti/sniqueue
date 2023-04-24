{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorSha256 = "sha256-zBjuC75yuN/NnQf/pnbmChV9dQKX/r3jbS2L9CUDc80=";

  subPackages = [ "./cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
