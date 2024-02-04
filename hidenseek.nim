import osproc, strformat, times
import std/[os]

from src/runCommand import runShellCommand

let t : float = cpuTime()

runShellCommand("clear")

case paramStr(1):
    of "-a" : #all
        runShellCommand(fmt"cd src && ./buildYara {paramStr(2)} && cd ..")
    of "-m" : #malware
        echo "pass"
    of "-s" :  #sort
        runShellCommand(fmt"python3 src/python/sortFilesComp.pyc {paramStr(2)}")
    of "-p" :  #process
        runShellCommand("")
    else : 
        runShellCommand("clear && source info.sh && help")

echo "Execution time : ", cpuTime() - t
