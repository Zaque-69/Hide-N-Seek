#[
  What this code do?
  This Nim program creates a Yara rule for each file by its extension.
  So, it can checks if the extension corespond with the signature
  of the file. This can by used to check if a downloaded file have its
  extension changed. SO it can be used as malware, fooling you.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures

  Z4que 2024 - All rights reserved
]#

import json, strutils
import std/[os,strformat, terminal]

#importing local files
from filelist import fileList
from runCommand import runShellCommand

#declaration of variables used

var
  yaraContent : string 
  yaraStructure : string
  list : array[10, string]
  filesFromDir : seq[string] = fileList(paramStr(1))

#creating a 'Yara' foldes in case it doesn't exists
try : runShellCommand("rm -r yara")
except : discard

#creating a 'Yara' foldes in case it doesn't exists
runShellCommand("mkdir yara")

#creating a 'Yara' foldes in case it doesn't exists
runShellCommand(fmt"python python/getExtensions.py {paramStr(1)}")

#returning the text from a file
proc readFileContent(filename: string): string =
    var
      file: File
      content: string

    if open(file, filename) : 
      content = readAll(file)

    close(file)
    return content

#main function
proc buildFile( extension : string ) =

  #creating or editing a .yara file
  proc writeYara(filename: string, content: string) =
    var 
      file: File

    if open(file, filename, fmWrite) :
      write(file, content)
      close(file)

  #returning the text from a file, especially from the 'extensions.json' file, 
  #which have the cost comm

  proc main( extensionFile : string) : void =
      
    let fileContent = readFileContent("json/extensions.json")
    let jsonData = parseJson(fileContent)
    let hexDecimals = jsonData[extensionFile].getStr()

    if len(hexDecimals) > 0 : list[0] = hexDecimals

    else : 
      for i in countup(0, 9) :
        try :
          let secondExtensionFile = extensionFile & intToStr(i)
          #               readFileContent("newww.txt") & 
          yaraStructure =  jsonData[extensionFile][secondExtensionFile].getStr()
          list[i] = yaraStructure
          yaraStructure = ""
          
        except : discard

  main(extension)

  proc buildYaraStructure(bytes : string) : void =

    #building a yara rule using the bytes from the extenion selected
    yaraContent = "rule find" & extension & " { \n strings : \n \n"
    for i in countup(0, 9): 
      if len(list[i]) > 0 : yaraContent &= "    $byte" & intToStr(i) & " = {" & list[i] & "} \n"
    yaraContent &= "\n condition : any of them"
    
    #deleting the last '$' from the contition
    yaraContent = yaraContent[0..len(yaraContent) - 1]

    #after deleting the last '$', we add an endline and close the bracket 
    yaraContent &= "\n }"

    #creating a file with the unsing the 'extension' parameter from main proc
    writeYara(fmt"yara/find{extension}.yara", yaraContent)

  for i in countup(0, 9 mod 2):
    if len(list[i]) > 0 : 
      buildYaraStructure(list[0])

#reading each line from "extentions.txt" file and create a Yara role for each
for line in lines "json/extensions.txt" : 
  try : buildFile(fmt"{line}")
  except : discard

#list of yara rules
var
  yaraRules : seq[string] = fileList("yara")
  extensionsInPath : seq[string]
  path : string = paramStr(1)

for line in lines "json/extensions.txt" : add(extensionsInPath, line)

#if the path argument is not finishing with "/" we will add one
if path[len(path) - 1] != '/' : path &= "/" 

for k in extensionsInPath:
  for i in filesFromDir:
    for j in yaraRules : 
      if len(j) > 0 and contains(i, k) and contains(j, k) : 
        
        runShellCommand(fmt"yara yara/{j} {path}{i} > auxiliary.txt")

        if len(readFileContent("auxiliary.txt")) == 0 : stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {path}{i} has extension changed!")
        else : stdout.styledWriteLine(fgGreen, styleBright, fmt"[0K!] File : {path}{i} has passed the test!")

      runShellCommand(" > auxiliary.txt ")


#clear && nim c -r buildYara.nim /home/z4que/workspace/hidenseek/src/
# yara rules and extensions
