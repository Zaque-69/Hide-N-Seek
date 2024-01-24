#[
    This code returns the file names from a directory
    in Nim. Using C, we can write the file names in a
    'output.txt' and with the procedure 'listdir' we 
    can return a sequence with the filenames.
 
    Z4que 2024 - All rights reserved
]#

import osproc, strformat

var count : int

proc createArray(size: int): seq[string] =
  return newSeq[string](size)

proc countRows(filename : string) : int = 
    for line in lines filename : count += 1
    return count 

proc fileList*( path : string ) : seq[string] =
    #witing the files from a path using C
    let runCommand : int = execCmd(fmt"clear && gcc main.c -o main && ./main {path}")

    #counting rows
    var rows : seq[string] = createArray(countRows("output.txt"))

    count = 0

    for line in lines "output.txt" : 
        rows[count] = line
        count += 1

    #deleting the first 2 rows that contain only dots
    delete(rows, 1)
    delete(rows, 0)

    let deleteTxt : int = execCmd("rm output.txt")

    return rows
