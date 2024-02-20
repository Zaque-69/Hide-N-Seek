#[
  What this code do?
  This Nim program creates a Yara rule for each file by its extension.
  So, it can checks if the extension corespond with the signature
  of the file. This can by used to check if a downloaded file have its
  extension changed. SO it can be used as malware, fooling you.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures

  Z4que 2024 - All rights reserved
]#

import json, strutils, os
import std/[os,strformat, terminal]

#importing local files
from runCommand import runShellCommand

#declaration of variables used

var
  yaraContent : string 
  yaraStructure : string
  list : array[10, string]
  filesFromDir : seq[string]
  yaraRules : seq[string]
  argPath : string = paramStr(1)

for file in walkDir(paramStr(1)) : 
  filesFromDir.add(file.path)

for file in walkDir("yara"): 
   yaraRules.add(file.path)

#creating a 'Yara' foldes in case it doesn't exists
runShellCommand("rm -rf yara && mkdir yara")
runShellCommand(fmt"nim c -r extensions.nim {paramStr(1)}")

proc buildFile( extension : string ) =
      
  let fileContent = readFile("json/extensions.json")
  let jsonData = parseJson(fileContent)
  let hexDecimals = jsonData[extension].getStr()

  if len(hexDecimals) > 0 : list[0] = hexDecimals

  else : 
    for i in countup(0, 9) :
      try :
        let secondExtensionFile = extension & intToStr(i)
        yaraStructure =  jsonData[extension][secondExtensionFile].getStr()
        list[i] = yaraStructure
        yaraStructure = ""
          
      except : discard

  proc buildYaraStructure(bytes : string) : void =

    #building a yara rule using the bytes from the extenion selected
    yaraContent = "rule find" & extension & " { \n strings : \n \n"
    for i in countup(0, 9): 
      if len(list[i]) > 0 : 
        yaraContent &= "    $byte" & intToStr(i) & " = {" & list[i] & "} \n"

    yaraContent &= "\n condition : any of them"
    yaraContent = yaraContent[0..len(yaraContent) - 1] 
    yaraContent &= "\n }"

    #creating a file with the unsing the 'extension' parameter from main proc
    writeFile(fmt"yara/find{extension}.yara", yaraContent)

  for i in countup(0, 9 mod 2):
    if len(list[i]) > 0 : 
      buildYaraStructure(list[0])

#reading each line from "extentions.txt" file and create a Yara role for each
for line in lines "json/extensions.txt" : 
  try : 
    buildFile(fmt"{line}")
  except : 
    discard

var
  extensionsInPath : seq[string]
  finalTrue : seq[string]
  finalFalse : seq[string]

for line in lines "json/extensions.txt" : 
  extensionsInPath.add(line)

#if the path argument is not finishing with "/" we will add one
if argPath[len(argPath) - 1] != '/' : argPath &= "/" 

#printing the infected files
for k in extensionsInPath:
  for i in filesFromDir:

    for j in yaraRules : 
      if len(j) > 0 and contains(i, k) and contains(j, k) :
        finalTrue.add(i)
        runShellCommand(fmt"clear && yara {j} {i}")
        stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {i} has extension changed!") 
  
#printing the regular files
for i in countup(0, len(filesFromDir) - 1) :
  for j in countup(0, len(finalTrue) - 1) :
    if filesFromDir[i] != finalTrue[j] :
      stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {filesFromDir[i]} has passed the test!")
      break

# j i
