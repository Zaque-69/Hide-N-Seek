{ pkgs ? import <nixpkgs> {} } : 

pkgs.mkShell{
  nativeBuildInputs = with pkgs; [
    yara
    nim
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
