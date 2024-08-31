import osproc
import std/[ terminal, strformat, os ]
import std/strutils

proc runShellCommand * ( command: string,  ) : void = 
  discard execCmd(command)

proc first_line( file : string ) : string =
  if not fileExists( file ):
    echo "File does not exist!"
    return

  let lines = readFile( file ).splitLines()

  if lines.len == 0:
    echo "File is empty!"
    return

  return lines[0]

proc compile_all * ( path, rm_ext : string ) : void =
  for file in walkDir( fmt "{path}") :
    if contains( file.path, "nim" ) : 
      runShellCommand( fmt "nim c {file.path}" )
    else : 
      runShellCommand( fmt "yarac {file.path} {file.path[0 .. len( file.path) - 6 ] }" )
  
proc echoStatusFile * ( file, rule : string, boolean : bool ) : void = 
  if boolean : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] {file} may contain malitious bytes : {rule}") 

proc has_extension_changed * ( file : string ) : void = 
  stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} has extension changed! Rule output : ", first_line("File/positive_rule.txt")) 