import os, osproc
import std/[ strformat, strutils ]

proc filelist * ( path : string ) : seq[string] =
    #Return the files from a path
    var list : seq[string] = @[] 
    for file in walkDir(path) : 
        add(list, file.path) 
    return list

proc compile_all * ( path, rm_ext : string ) : void =
  for file in walkDir( fmt "{path}") :
    if contains( file.path, "nim" ) : 
      discard execCmd( fmt "nim c {file.path}" )
    else : 
      discard execCmd( fmt "yarac {file.path} {file.path[0 .. len( file.path) - 6 ] }" )
  
proc runShellCommand *( command : string ) : void = 
    discard execCmd(command)