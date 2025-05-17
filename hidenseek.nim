import 
    os,
    strformat, 
    times

from src/shell import runShellCommand
from src/helpers import compileAll

# The main procedure
proc main() = 

    let 
        initTime : float = cpuTime()

    case paramStr(1):
        of "-e" : #all
            runShellCommand(fmt"cd src && nim c -r buildyara.nim {paramStr(2)} && cd ..")

        of "-m" :
            runShellCommand(fmt"cd src && nim c -r malware.nim {paramStr(2)} && cd ..")

        of "-c" : 
            compileAll("src", "nim")
            compileAll("src/rules", "yara")

        else : 
            runShellCommand("nim c -r info.nim")

    echo "Execution time : ", cpuTime() - initTime

if isMainModule : 
    main()