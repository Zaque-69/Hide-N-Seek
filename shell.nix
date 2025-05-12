{ pkgs ? import <nixpkgs> {} } : 

pkgs.mkShell{
  nativeBuildInputs = with pkgs; [
    yara
    nim
    upx
    nim
    python313
    python313Packages.tkinter
    python313Packages.customtkinter
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
