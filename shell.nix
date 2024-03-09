{ pkgs ? import <nixpkgs> {} } : 

pkgs.mkShell{
  nativeBuildInputs = with pkgs; [
    yara
    nim2
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
