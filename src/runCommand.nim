import osproc
import std/[ terminal, strformat, os ]
import std/strutils

proc runShellCommand * ( command: string,  ) : void = 
  discard execCmd(command)

proc compile_all * ( path, rm_ext : string ) : void =
  for file in walkDir( fmt "{path}") :
    if contains( file.path, "nim" ) : 
      runShellCommand( fmt "nim c {file.path}" )
    else : 
      runShellCommand( fmt "yarac {file.path} {file.path[0 .. len( file.path) - 5 ] }" )
    
  for file in walkDir( fmt "{path}") :
    if contains( file.path, rm_ext ) : 
      runShellCommand( fmt "rm {file.path}" )

proc echoStatusFile * ( file, rule : string, boolean : bool ) : void = 
  if boolean : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} may be malitious. Reason : {rule}.") 

proc has_extension_changed * ( file : string, boolean : bool ) : void = 
  if boolean : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} has extension changed!") 
