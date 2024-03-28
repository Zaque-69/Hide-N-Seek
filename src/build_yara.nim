#[
  What this code do?
  With the 'extensions.nim' file, we can check if a file have its extension changed
  based on each file signature. This code build a YARA rule for each extension from a dir.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures

  Z4que 2024 - All rights reserved
]#

import json, strutils, os, strformat
from runCommand import runShellCommand, has_extension_changed

var 
  yaraContent : string 
  yaraStructure : string
  list : seq[string]
  filesFromDir : seq[string]
  yara_rules : seq[string]
  extensionsInPath : seq[string]
  argPath : string = paramStr(1)

  boolean : bool = false

#[ creating a 'Yara' foldes in case it doesn't exists ]#
if not dirExists("yara") : 
  createDir("yara")
runShellCommand(fmt"nim c -r extensions.nim {paramStr(1)}")

#[ adding the files from the selected path to a sequence ]#
for file in walkDir(paramStr(1)) : 
  add(filesFromDir, file.path)

#[ adding the YARA rules to a sequence ]#
for file in walkDir("yara"): 
  add(yara_rules, file.path)

#[ returning the words from a positive YARA rule ]#
proc return_yara_result( file : string ) : seq[string] = 
  return readFile(file).split(' ')

proc build_yara_structure(ext : string) : void =
  #[ building a yara rule using the bytes from the extenion selected ]#
  yaraContent = "rule find" & ext & " { \n strings : \n \n"
  for i in countup(0, 9): 
    if len(list[i]) > 0 : 
      yaraContent &= "    $byte" & intToStr(i) & " = {" & list[i] & "} \n"

  yaraContent &= "\n condition : any of them"
  yaraContent = yaraContent[0..len(yaraContent) - 1] 
  yaraContent &= "\n }"

  #[ creating a file with the unsing the 'extension' parameter from main proc ]#
  writeFile(fmt"yara/find{ext}.yara", yaraContent)

proc build_yara_file( extension : string ) =
  #[ creating a YARA rule as a file ]#
  let jsonData = parseJson(readFile("json/extensions.json"))
  let hexDecimals = jsonData[extension].getStr()

  if len(hexDecimals) > 0 : 
    list[0] = hexDecimals

  else : 
    for i in countup(0, 9) :
      try :
        let secondExtensionFile = extension & intToStr(i)
        yaraStructure =  jsonData[extension][secondExtensionFile].getStr()
        list[i] = yaraStructure
        yaraStructure = ""
          
      except : discard

  for i in countup(0, 9 mod 2):
    if len(list[i]) > 0 : 
      build_yara_structure(extension)

#[
  we use 'try' statement because is the 'json/extensions.json' file there are maximum
  9 different headers for some extensions, and in the selected files from the path we 
  don't know how many headers could be for the extensions ( could be 2, 4, etc. )
]#
for line in lines "File/extensions.txt" : 
  try : 
    build_yara_file(line)
  except : 
    discard

for line in lines "File/extensions.txt" : 
  extensionsInPath.add(line)

#[ if the path argument is not finishing with "/" we will add one ]#
if argPath[len(argPath) - 1] != '/' : 
  argPath &= "/" 

#[ printing the infected files ]#
for img in filesFromDir : 
  for rule in yara_rules : 
    runShellCommand(fmt"yara {rule} {img} > File/positive_rule.txt")

    if ( len("File/positive_rule.txt") > 0 ) : 
      var words : seq[string] = return_yara_result("File/positive_rule.txt")
      if ( len(words) > 0 ) : 
        for ext in extensionsInPath : 
          if contains(words[0], ext) and contains(words[1], ext) : 
            boolean = true

  if boolean : 
    has_extension_changed(img, false)
  else : 
    has_extension_changed(img, true)

  boolean = false
