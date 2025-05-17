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
    python313Packages.pillow
    python313Packages.pip
  ];

  shellHook = ''
    echo "Shell prepared!"
  '';
}
