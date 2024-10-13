import strformat, times
import std/[os]

from src/common import compile_all, runShellCommand

let t : float = cpuTime()

case paramStr(1):
    of "-e" : #all
        runShellCommand(fmt"cd src && nim c -r buildyara.nim {paramStr(2)} && cd ..")
    of "-m" : #malware
        runShellCommand(fmt"cd src && nim c -r malware.nim {paramStr(2)} && cd ..")
    of "-p" :  #process
        runShellCommand("")
    of "-c" : 
        compile_all("src", "nim")
        compile_all("src/rules", "yara")
    else : 
        runShellCommand("./info.sh")

echo "Execution time : ", cpuTime() - t
