
import 
    osproc,
    strformat

proc echoWarning * ( file, positiveRule : string ) : void = 
    echo positiveRule, " ", file

proc hasExtensionChanged * ( path : string ) : void = 
    echo fmt"[!] EXT : {path} has extension changed!"

proc runShellCommand *( command : string ) : void = 
    # Running a shell comand
    
    discard execCmd(command)

proc runCommandSequence * (commands: seq[string]) : void =
    # Running shell comands from a sequence

    for command in commands:
        echo command
        discard execCmdEx(command)
