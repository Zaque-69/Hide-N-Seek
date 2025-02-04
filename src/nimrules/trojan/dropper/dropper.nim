import 
    os
    
from ../COMMON/file import 
    fileSize

from ../COMMON/header import
    checkHeaderELF

from ./helpers/strings import
    removeLocalIPs, 
    suspiciousCommandsDroperTrojan,
    suspiciousIPCombinationDroperTrojan,
    virusRaportTrojan

from ./helpers/file import 
    checkEachSuspiciousLine,
    allIPsFromFile

 # Counting conditions to validate the virus
proc checkFileDropperTrojan(filename : string) : void = 
    var 
        count : int = 0
        suspicious_ips : seq[string] = @[]
    
    let
        suspicious_commands : seq[string] = checkEachSuspiciousLine(filename, suspiciousCommandsDroperTrojan())
        ips : seq[string] = removeLocalIPs(allIPsFromFile(filename))

    try : 
        if len(ips) > 0 : 

            # Checking for 'weird' combinations of strings with public IPs
            for ip in ips : 
                suspicious_ips &= checkEachSuspiciousLine(filename, suspiciousIPCombinationDroperTrojan(ip))

            if len(suspicious_ips) > 1 : 
                count += 1

            if len(suspicious_commands) > 1 : 
                count += 1

            # Checking for a specific dimension of the file 
            if fileSize(60000, 200000, filename) : 
                count += 1

            # Checking for if the file have a Linux executable header
            if checkHeaderELF(filename) : 
                count += 1
        
        if ( count >= 4 ) or ( count >= 3 and not checkHeaderELF(filename) ): 
            echo "Linux_dropper_trojan_" & filename[0..7], filename
            
    except OSError : 
        discard

# Recursive function to scan the files from a path
proc scanFilesDropperTrojan * (path : string) : void = 

    for file in walkDir(path, false, true) : 
        if file.kind == pcFile : 
            checkFileDropperTrojan(file.path) 
           
        else : 
            scanFilesDropperTrojan(file.path)
