import osproc, strformat ,std/os

proc runCommad( command : string ) : void =
    let run : int = execCmd(command)

case paramStr(1):
    of "-h" : 
        runCommad("cd src && nim c -r info.nim && cd ..")
    of "-i" : 
        runCommad(fmt"cd src && nim c -r buildYara.nim {paramStr(2)} && cd ..")
    else : discard