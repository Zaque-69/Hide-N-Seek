import osproc, strformat
import std/[os]

var
    local : seq[string] = @["ransomware", "miner"]

proc runCommad( command : string ) : void =
    let run : int = execCmd(command)

case paramStr(1):
    of "-a" : 
        runCommad(fmt"clear && cd src && nim c -r buildYara.nim {paramStr(2)} && cd ..")
    of "-m" : 
        for i in countup(0, len(local) - 1) : 
            runCommad(fmt"clear && yara src/malware/{local[i]}.yara {paramStr(2)}")
    of "-s" :  
        runCommad(fmt"python src/python/sortFilesComp.pyc {paramStr(2)}")
    else : 
        runCommad("clear && cd src && nim c -r info.sh && cd ..")
