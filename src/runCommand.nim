import osproc
import std/[terminal, strformat]

proc runShellCommand*(command: string) : void = 
  discard execCmd(command)

proc echoStatusFile*(file, rule : string, boolean : bool) : void = 
  if boolean : 
    stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {file} has passed the {rule} test!")
  else : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} may be malitious. Reason : {rule}.") 

proc has_extension_changed*( file : string, boolean : bool ) : void = 
  if not boolean : 
    stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {file} has passed the test!")
  else : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} has extension changed!") 
