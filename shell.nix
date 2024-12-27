{ pkgs ? import <nixpkgs> {} } : 

pkgs.mkShell{
  nativeBuildInputs = with pkgs; [
    bless
    yara
    nim
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
