
import 
    osproc,
    strformat,
    std/terminal

# Echo the warning output of a PUA file
proc echoWarning * ( file, positiveRule : string ) : void = 
    stdout.styledWriteLine(
        fgRed, 
        styleBright, 
        fmt"[WARNING!] Path {file} may contain malitious bytes : {positiveRule}"
    )

# Echo the warning output of a file with extension changed
proc hasExtensionChanged * ( path : string ) : void = 
    stdout.styledWriteLine(
        fgRed, 
        styleBright, 
        fmt"[WARNING!] File : {path} has extension changed!" & '\n'
    ) 

# Running a shell comand
proc runShellCommand *( command : string ) : void = 
    discard execCmd(command)