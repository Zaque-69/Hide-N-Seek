import 
    os,
    re,
    strutils

# Boolean to check the size of a file 
proc fileSize * (min_size : int, max_size : int, filename : string) : bool = 
    if os.getFileSize(filename) > min_size and os.getFileSize(filename) < max_size :
        return true
    false

proc checkEachSuspiciousLine * (filename : string, sequence : seq[string]) : seq[string] =
    for line in lines(filename) : 
        for element in sequence : 
            if contains(line, element) : 
                add(result, element)
    result

# Deleting a file if exists
proc deleteFile * (filePath: string) : void =
    if fileExists(filePath) :
        removeFile(filePath)    

# Extracting all the IPs from a file by REGex by reading each line
proc allIPsFromFile * (filename: string): seq[string] =
    var 
        list: seq[string] = @[]
        ipRegex = re"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    
    for line in lines(filename):
        list.add(findAll(line, ipRegex))

    list