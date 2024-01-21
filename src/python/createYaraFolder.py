import os
home = os.getcwd()
os.chdir("..")
if not os.path.exists("yara") : os.mkdir("yara")
os.chdir(home)