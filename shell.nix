{ pkgs ? import <nixpkgs> {} } : 

pkgs.mkShell{
  nativeBuildInputs = with pkgs; [
    yara
    nim
    upx
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
