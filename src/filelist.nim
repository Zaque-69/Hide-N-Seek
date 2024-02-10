#[
    This code returns the file names from a directory
    in Nim. Using C, we can write the file names in a
    'output.txt' and with the procedure 'listdir' we 
    can return a sequence with the filenames.
 
    Z4que 2024 - All rights reserved
]#

import osproc, strformat, strutils
from runCommand import runShellCommand

proc createArray(size: int): seq[string] =
  return newSeq[string](size)

proc countRows(filename : string) : int = 
    var count : int = 0
    for line in lines filename : count += 1
    return count + 1

proc fileList*( path : string ) : seq[string] =
    var 
      content : string   
      count : int = 0
  
    #witing the files from a path using C
    runShellCommand(fmt"cd c && touch output.txt && gcc filelist.c -o main && ./main {path} && mv output.txt .. && cd ..")

    var rows = createArray(countRows("output.txt"))

    for line in lines "output.txt" :   
      rows[count] = line
      count += 1

     
    #runShellCommand("rm output.txt")
    return rows
