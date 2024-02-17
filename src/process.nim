from runCommand import runShellCommand
from filelist import fileList
import std/[os, terminal, strformat], times, strutils

let t : float = cpuTime()

var
    file: File
    content: string
    yaraRules : seq[string] = @["ransomware.yara", "miner.yara", "others.yara"]

proc deleteLineFromString(inputStr: string, lineNum: int): string =
    var lines = inputStr.splitLines()
    
    if lineNum >= 0 and lineNum < lines.len:
        lines.del(lineNum)
    
    return lines.join("\n")

#extraxcting all the processes name files from after running the C compiled file
#runShellCommand("touch c/process.txt && c/process && mv c/process.txt .")

if paramStr(1) == "-p" : 
  runShellCommand("clear && touch c/process.txt && c/process && mv c/process.txt . && sudo su")
  for i in yaraRules:
    for line in lines "process.txt" : 
      try :
        if contains(readFile("aux.txt"), "error") :
          discard

        elif len(readFile("aux.txt")) == 0 :
          stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {line} has passed the test!", readFile("yaraLines.txt"))

        else : 
          stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {line} may be malitious! Reason : ", deleteLineFromString(readFile("yaraLines.txt"), 1))
        
      except:
        discard

echo "\nExecution time : ", cpuTime() - t
