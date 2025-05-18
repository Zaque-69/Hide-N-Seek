import 
    os
    
from ../../COMMON/file import 
    fileSize

from ./helpers/strings import
    suspiciousCommandsDownloaderShell,
    suspiciousIPCombinationDownloaderShell

from ./helpers/file import 
    checkEachSuspiciousLine,
    allIPsFromFile

 # Counting conditions to validate the virus
proc checkFileDropperTrojan(filename : string) : void = 
    var 
        count : int = 0
        suspicious_ips : seq[string] = @[]
    
    let
        suspicious_commands : seq[string] = checkEachSuspiciousLine(filename, suspiciousCommandsDownloaderShell())
        ips : seq[string] = allIPsFromFile(filename)

    try : 
        if len(ips) > 0 : 

            # Checking for 'weird' combinations of strings with public IPs
            for ip in ips : 
                suspicious_ips &= checkEachSuspiciousLine(filename, suspiciousIPCombinationDownloaderShell(ip))

            if len(suspicious_ips) > 0 : 
                count += 1

            if len(suspicious_commands) > 0 : 
                count += 1

            # Checking for a specific dimension of the file 
            if fileSize(50, 10000, filename) : 
                count += 1
        
        if ( count == 3 ) : 
            echo "Linux_shell_downloader " & filename
            
    except OSError : 
        discard

# Recursive function to scan the files from a path
proc scanFilesDownloaderShell * (path : string) : void = 

    for file in walkDir(path, false, true) : 
        if file.kind == pcFile : 
            checkFileDropperTrojan(file.path) 
           
        else : 
            scanFilesDownloaderShell(file.path)
