
import std/strformat, osproc, os, nimpy

let clearCmd : int = execCmd(fmt"clear")
echo clearCmd

echo """▒█░▒█ ░▀░ █▀▀▄ █▀▀   █ ▒█▄░▒█   ▒█▀▀▀█ █▀▀ █▀▀ █░█ 
        ▒█▀▀█ ▀█▀ █░░█ █▀▀   ░ ▒█▒█▒█   ░▀▀▀▄▄ █▀▀ █▀▀ █▀▄ 
        ▒█░▒█ ▀▀▀ ▀▀▀░ ▀▀▀   ░ ▒█░░▀█   ▒█▄▄▄█ ▀▀▀ ▀▀▀ ▀░▀
     """

proc pass() = return

proc showCurrentDirrectoryFiles(path : string) : void =
    pass()

proc executeYaraRule(file, path : string) : void =
    let yaraRuleFile : bool = fileExists(file)
    let ansBool : int = execCmd(fmt"yara {file} {path}")


    if ansBool == 1 : 
        if yaraRuleFile == false : 
            echo fmt"File '{file}' doesn't exist."
            return 
        else : 
            echo fmt"Path {path}' doesn't exist."
            return 

    #echo ansBool;

#executeYaraRule("main.yara", "/home/z4que/Downloads")
showCurrentDirrectoryFiles("")
