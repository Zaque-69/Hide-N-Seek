import
    os,
    strformat,
    strutils

from ../COMMON/shell import 
    runShellCommand

# Deleting the possible viruses from the "files/" directory
proc refreshOutputFiles() : void = 
    for file in walkDir("files/upx") : 
        removeFile(file.path)

# Running the yara rule to find compressed UPX files
proc runYaraRuleForUpx( path : string ) : void = 
    runShellCommand(fmt"yara nimrules/trojan/upx/Linux_upx.yara {path} > files/upx.txt")

# Getting the names of the files compressed 
proc filenamesFromOutput() : seq[string] = 
    for line in lines "files/upx.txt" : 
        add(result, line.split()[1].replace("//", "/"))

# Moving the possible viruses to "files/upx" to scan
proc copyUpxFiles( path : string ) : void = 
    for file in filenamesFromOutput() :
        runShellCommand(fmt" cp {file} files/upx")

# Decompiling the files
proc decompileUpxCopiedFiles() : void = 
    for file in walkDir("files/upx") :
        runShellCommand(fmt"upx -d {file.path}")

proc scanFilesUpx * ( path : string ) : void =
    refreshOutputFiles() 
    runYaraRuleForUpx(path)
    copyUpxFiles(path)
    decompileUpxCopiedFiles()
