{ pkgs ? import <nixpkgs> { }
, src ? ./.
, buildGoModule
, fetchFromGithub
,
}:

buildGoModule rec {
  name = "sniqueue";
  inherit src;

  vendorHash = "sha256-IKZImxnCFpgsEQFcGTdkuC28tnZP5rJMourwE0ggIo8=";

  subPackages = [ "cmd/sniqueue" ];

  meta = {
    description = "SNIQueue";
    homepage = "https://github.com/jsimonetti/sniqueue";
  };
}
