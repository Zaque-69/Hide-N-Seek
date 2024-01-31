import osproc, strformat
import std/[os]

var
    local : seq[string] = @["ransomware", "miner"]

proc runCommand( command : string ) : void =
    let run : int = execCmd(command)

case paramStr(1):
    of "-a" :
        runCommand(fmt"cd src && nim c -r buildYara.nim {paramStr(2)} && cd ..")
    of "-m" :
        runCommand("clear")
        for i in countup(0, len(local) - 1) :
            #echo fmt"yara src/malware/{local[i]}.yara {paramStr(2)}"
            runCommand(fmt"yara src/malware/{local[i]}.yara {paramStr(2)}")
    of "-s" :
        runCommand(fmt"python3 src/python/sortFilesComp.pyc {paramStr(2)}")
    else :
        runCommand("clear && cd src && nim c -r info.sh && cd ..")
