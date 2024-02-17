{
  description = "Hide 'N Seek flake installation for NixOS;";

  inputs = {
    nixpkgs = {
      url = github:nixos/nixpkgs/nixos-unstable;
    };
  };

  outputs = {
    self,
    nixpkgs,
  } : let
    system = "x86_64-linux";
    pkgs = nixpkgs.legacyPackages.${system};

  in {
    devShells.${system}.default = 
      pkgs.mkShell {
        buildInputs = [
          pkgs.nim2
          pkgs.yara
          pkgs.gcc
      ];
    };
  };
}
