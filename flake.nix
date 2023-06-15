{
  description = "SNIQueue";
  inputs.nixpkgs.url = "nixpkgs/nixos-23.05";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.treefmt-nix.url = "github:numtide/treefmt-nix";
  inputs.treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, flake-utils, treefmt-nix }:
    flake-utils.lib.eachDefaultSystem (system: {
      formatter = treefmt-nix.lib.mkWrapper nixpkgs.legacyPackages.${system}
        {
          projectRootFile = "flake.nix";
          programs.nixpkgs-fmt.enable = true;
          programs.gofmt.enable = true;
        };

      defaultPackage = self.packages.${system}.default;

      packages = {
        default = self.packages.${system}.sniqueue;

        sniqueue = nixpkgs.legacyPackages.${system}.callPackage self {
          src = self;
        };
      };

      devShells = {
        default = nixpkgs.legacyPackages.${system}.mkShell {
          buildInputs = with nixpkgs.legacyPackages.${system}; [ go gopls go-tools gotools jq yq ];
        };
      };
    });
}
