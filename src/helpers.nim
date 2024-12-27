
import 
    os, 
    sequtils, 
    std/[
        strutils,
        strformat
    ]

from shell import 
    runShellCommand

#Compiling all the "Nim" files
proc compileAll * ( path, rm_ext : string ) : void =
  for file in walkDir( fmt "{path}") :
    if contains( file.path, "nim" ) : runShellCommand( fmt "nim c {file.path}" )
    else : runShellCommand( fmt "yarac {file.path} {file.path[0 .. len( file.path) - 6 ] }" )

# Return the files from a path
proc fileList * ( path : string ) : seq[string] =
    var list : seq[string] = @[] 
    for file in walkDir(path) : 
        add(list, file.path) 
    return list

# Returning a string with your OS
proc returnOS * () : string = 
    when defined windows: 
        return "windows"
    return "linux"

 # Transforming a string to a sequence
proc stringToSequence * ( file : string ) : seq[string] = 
    return file.split().filterIt(it != "")