import os, subprocess

for file in os.listdir(".") : 
    subprocess.call(f"yara {file} /home/z4que/Downloads/6d7598660a777e5feb3095cd1f30a85f1eb8ee89ed974763894b6354a0a5beb8.elf", shell = True)