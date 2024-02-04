from runCommand import runShellCommand
from filelist import fileList
import std/[os, terminal, strformat], times, strutils

let t : float = cpuTime()

var
    file: File
    content: string
    path : string = paramStr(2)
    yaraRules : seq[string] = @["ransomware.yara", "miner.yara", "others.yara"]

if path[len(path) - 1] != '/' : path &= "/" 


proc readFileContent(filename: string): string =
    if open(file, filename) : 
      content = readAll(file)

    close(file)
    return content

proc deleteLineFromString(inputStr: string, lineNum: int): string =
    var lines = inputStr.splitLines()
    
    if lineNum >= 0 and lineNum < lines.len:
        lines.del(lineNum)
    
    return lines.join("\n")

#extraxcting all the processes name files from after running the C compiled file
runShellCommand("cd c && touch process.txt && ./process && mv process.txt ..")


if paramStr(1) == "-p" : 

    for i in yaraRules:
        for line in lines "process.txt" : 

            #running the Yara rules for every process from the file
            runShellCommand(fmt"yara malware/{i} {line} > yaraLines.txt")

            #Showing the result depending on what the Yara rules found
            if len(readFileContent("yaraLines.txt")) == 0 : 
                stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {line} has passed the test!", readFileContent("yaraLines.txt"))
            else : 
                stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {line} may be malitious! Reason : ", deleteLineFromString(readFileContent("yaraLines.txt"), 1))

            #delete the text from the file
            runShellCommand(" > yaraLines.txt ")

elif paramStr(1) == "-m":

    for i in yaraRules:
        for line in fileList(path) : 

            runShellCommand(fmt"yara malware/{i} {line} > yaraLines.txt")

            if len(readFileContent("yaraLines.txt")) == 0 : 
                stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {line} has passed the test!", readFileContent("yaraLines.txt"))
            else : 
                stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {line} may be malitious! Reason : ", deleteLineFromString(readFileContent("yaraLines.txt"), 1))

            runShellCommand(" > yaraLines.txt ")

    echo "Execution time : ", cpuTime() - t

else : 
    echo "Command not found."