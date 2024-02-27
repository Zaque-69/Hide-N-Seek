from runCommand import runShellCommand
import std/[os, terminal, strformat], times, strutils

let t : float = cpuTime()

var
    file: File
    content: string
    yaraRules : seq[string] = @[]

#adding the YARA rules from the 'malware' foler in a sequence
for file in walkDir("malware") : 
  add(yaraRules, file.path)

proc deleteLineFromString(inputStr: string, lineNum: int): string =
    var lines = inputStr.splitLines()
    
    if lineNum >= 0 and lineNum < lines.len:
        lines.del(lineNum)
    
    return lines.join("\n")

#adding the running processes in a file and the we will scan them
runShellCommand(" > File/process.txt && ps -ef --no-headers | awk '{print $8}' > File/process.txt ")

for line in lines "File/process.txt" :
  for i in yaraRules :
    if not contains(line, '[') and not contains(line, '(') and contains(line, '/') :
      runShellCommand(fmt"yara {i} {line} > File/outputProcess.txt")

      if len(readFile("File/outputProcess.txt")) == 0 : 
        stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {line} has passed the test!", readFile("yaraLines.txt"))
    
      else :
        stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {line} may be malitious! Reason : ", deleteLineFromString(readFile("yaraLines.txt"), 1))

for line in lines "File/process.txt" : 
  #we select only files that runs in background and not contains '[ ]' or '( )' -> kernel processes
  if not contains(line, '/') and not contains(line, '[') and not contains(line, '('):
    runShellCommand(fmt"echo '{line}' >> File/process2.txt")
  
echo "\nExecution time : ", cpuTime() - t
