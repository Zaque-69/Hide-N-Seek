import std/strformat, osproc, os, nimpy, times

let clearCmd : int = execCmd(fmt"clear")
echo clearCmd

echo """
▒█░▒█ ░▀░ █▀▀▄ █▀▀   █ ▒█▄░▒█   ▒█▀▀▀█ █▀▀ █▀▀ █░█ 
▒█▀▀█ ▀█▀ █░░█ █▀▀   ░ ▒█▒█▒█   ░▀▀▀▄▄ █▀▀ █▀▀ █▀▄ 
▒█░▒█ ▀▀▀ ▀▀▀░ ▀▀▀   ░ ▒█░░▀█   ▒█▄▄▄█ ▀▀▀ ▀▀▀ ▀░▀
     """

proc pass() = return

proc setCurrentDirectory( path : string ) : void =
    let importPyOs = pyImport("os")
    if len( path ) == 0 : discard importPyOs.chdir( getCurrentDir() )
    else : discard pyImport("os").chdir( path )
    #setCurrentDirectory("path/")

proc extensions( path : string ) = 
    let currentDir = getCurrentDir()
    let runPy : int = execCmd(fmt"python python/main.py {path}")
    let moveFile : int = execCmd(fmt"mv {path}aux.txt {currentDir}/Files")

proc showCurrentDirrectoryFiles(path : string) : void = pass()

proc runFilePath(file, path : string) : void =
    
    let file : bool = fileExists(file)
    let ansBool : int = execCmd(fmt"yara {file} {path}")

    if ansBool == 1 : 
        if file == false : 
            echo fmt"File '{file}' doesn't exist."
            return 
        else : 
            echo fmt"Path {path}' doesn't exist."
            return 

    #echo ansBool;

#runFilePath("main.yara", "/home/z4que/Downloads")
#showCurrentDirrectoryFiles("")

let initCpuTime : float = cpuTime()

extensions("/home/z4que/workspace/Graphite-kde-theme/")

echo "File Execution finished in ", cpuTime() - initCpuTime
