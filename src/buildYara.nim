#[
  What this code do?
  This Nim program creates a Yara rule for each file by its extension.
  So, it can checks if the extension corespond with the signature
  of the file. This can by used to check if a downloaded file have its
  extension changed. SO it can be used as malware, fooling you.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures

  Z4que 2024 - All rights reserved
]#

import json, times, strutils, osproc
import std/[os,strformat]

#declaration of variables used
let init : float = cpuTime()
var
    yaraContent : string 
    yaraStructure : string
    list : array[10, string]
    countFileElements : int

#creating a 'Yara' foldes in case it doesn't exists
let creatingFolderIfNoExists : int = execCmd("python python/createYaraFolder.py")

#creating a 'Yara' foldes in case it doesn't exists
let getExtensionsFromAPAth : int = execCmd(fmt"python python/getExtensions.py {paramStr(1)}")

#returning the text from a file
proc readFileContent(filename: string): string =
    var
      file: File
      content: string

    if open(file, filename) : content = readAll(file)

    close(file)
    return content

proc buildFile( extension : string ) =

  #passing procedure, the equivalent of 'pass' in Python
  proc pass() = return

  #creating or editing a .yara file
  proc writeYara(filename: string, content: string) =
    var 
      file: File

    if open(file, filename, fmWrite) :
      write(file, content)
      close(file)

  #returning the text from a file, especially from the 'extensions.json' file, 
  #which have the cost common file extensions used

  proc main( extensionFile : string) : void =
      
    let fileContent = readFileContent("extensions.json")
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
          
        except : pass()

  main(extension)

  proc buildYaraStructure(bytes : string) : void =

    #building a yara rule using the bytes from the extenion selected
    yaraContent = "rule find" & extension & " { \n strings : \n \n"
    for i in countup(0, 9): 
      if len(list[i]) > 0 : yaraContent &= "    $byte" & intToStr(i) & " = {" & list[i] & "} \n"
    yaraContent &= "\n condition : "
    for i in countup(0, 9): 
      if len(list[i]) > 0 : yaraContent &= "$byte" & intToStr(i) & " and "

    #deleting the last '$' from the contition
    yaraContent = yaraContent[0..len(yaraContent) - 6]

    #after deleting the last '$', we add an endline and close the bracket 
    #( &= is equal to += and is uised for strings )
    yaraContent &= "\n }"

    #creating a file with the unsing the 'extension' parameter from main proc
    writeYara(fmt"yara/find{extension}.yara", yaraContent)

  for i in countup(0, 9 mod 2):
    if len(list[i]) > 0 : 
      buildYaraStructure(list[0])

#////////////////////////////////////

#reading each line from "extentions.txt" file and create a Yara role for each
for line in lines "json/extensions.txt" : 
  try : buildFile(fmt"{line}")
  except : discard

echo "Execution time : ", cpuTime() - init
