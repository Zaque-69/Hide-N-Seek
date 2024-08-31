import asyncdispatch, os
import std/[strformat, strutils]
from runCommand import echoStatusFile, runShellCommand

var
  path : string = paramStr(1)
  files : seq[string]
  yaraRules : seq[string]
  check : bool = false 

for i in walkDir(path) : 
  files.add(i.path)

for i in walkDir("rules") : 
  yaraRules.add(i.path)

func deleteByName( lst : seq[string], name : string ) : seq[string] = 
  var lst2 : seq[string]
  for i in countup(0, len(lst) - 1) :
    if lst[i] != name : lst2.add(lst[i])
  
  result = lst2

func seqDifference(lst1, lst2 : seq[string]) : seq[string] = 
  var 
    l1 = lst1
    l2 = lst2

  var finalSeq : seq[string] = l2

  for i in countup(0, len(l2) - 1) :
    for j in countup(0, len(l1) - 1) :
      if l2[i] == l1[j] : finalSeq = deleteByName(finalSeq, l1[j])
  
  result = finalSeq

proc first_words(filename: string) : seq[string] =
  var list : seq[string] = @[]
  for line in filename.lines:
    add(list, line.split(' ')[0])

  return list


proc listen( location : string ) : Future[void] {.async.} = 
  var 
    files2 : seq[string] 
    
  while true : 
    await sleepAsync(10)
    for file in walkDir(location) :
      files2.add(file.path)
    
    if len(seqDifference(files, files2)) > 0 : 
      var fin = seqDifference(files, files2)
      for i in fin : 
        for j in yaraRules :
          runShellCommand(fmt" > File/positive_rule.txt && yara {j} {i} > File/positive_rule.txt ")
          
          if ( len(readfile("File/positive_rule.txt")) > 0 ) : 
            if not check : 
              var rules : seq[string] = first_words("File/positive_rule.txt")
              echoStatusFile(i, rules.join(", "), true)
              check = true;

    setLen(files2, 0)

proc main() {.async.} = 
  runShellCommand("clear")
  await listen(path)

waitFor main()
