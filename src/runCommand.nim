import osproc, strutils
import std/[terminal, strformat]

proc runShellCommand*(command: string) : void = 
  let result = execCmd(command)

proc echoStatusFile*(file : string, boolean : bool) : void = 
  if boolean : 
    stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {file} has passed the test!")
  else : 
    stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} has extension changed!") 
