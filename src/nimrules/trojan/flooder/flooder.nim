import 
    os

from ../COMMON/file import 
    fileSize

from ../COMMON/header import 
    checkHeaderELF

from helpers/strings import 
    allDatesFromFile

proc checkFileFlooderTrojan(filename : string) : void = 

    let suspicious_date : seq[string] = allDatesFromFile(filename)
    var count : int = 0

    if len(suspicious_date) > 0 : 
        count += 1

        # Checking for a specific dimension of the file 
        if fileSize(5000, 15000, filename) : 
            count += 1

        # Checking for if the file have a Linux executable header
        if checkHeaderELF(filename) : 
            count += 1
        
        if ( count >= 3 ) or ( count >= 2 and not checkHeaderELF(filename) ): 
            echo "flooder_trojan ", filename

# Recursive function to scan the files from a path
proc scanFilesFlooderTrojan * (path : string) : void = 

    for file in walkDir(path, false, true) : 
        if file.kind == pcFile : 
            checkFileFlooderTrojan(file.path) 

        else : scanFilesFlooderTrojan(file.path)
