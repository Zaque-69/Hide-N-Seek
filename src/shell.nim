
import 
    osproc,
    strformat,
    std/terminal

proc echoWarning * ( file, positiveRule : string ) : void = 
    # Echo the warning output of a PUA file

    stdout.styledWriteLine(
        fgRed, 
        styleBright, 
        fmt"[WARNING!] Path {file} may contain malitious bytes : {positiveRule}"
    )

proc hasExtensionChanged * ( path : string ) : void = 
    # Echo the warning output of a file with extension changed

    stdout.styledWriteLine(
        fgRed, 
        styleBright, 
        fmt"[WARNING!] File : {path} has extension changed!" & '\n'
    ) 

proc runShellCommand *( command : string ) : void = 
    # Running a shell comand
    
    discard execCmd(command)

