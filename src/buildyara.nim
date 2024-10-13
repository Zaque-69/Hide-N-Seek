#[
  With the 'extensions.nim' file, we can check if a file have its extension changed
  based on each file signature. This code build a YARA rule for each extension from a dir.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures
  Z4que 2024 - All rights reserved
]#

import json, strutils, os, strformat, sequtils, std/terminal
from common import filelist, runShellCommand

var
  jsonData = parse_json(readFile("json/extensions.json"))   #Parsed data from 'json/extensions.json'
  argument : string = paramStr(1)                           #The argument
  rules : seq[string] = @[]                                 #List with the rules created based on extensions
  argFiles : seq[string] = @[]                              #List with the arguments from the dir
  extensions_in_path : seq[string] = @[]                    #List with the extensiosn in the argument dir

proc has_extension_changed * ( file : string ) : void = 
  stdout.styledWriteLine(fgRed, styleBright, fmt"[WARNING!] File : {file} has extension changed!") 

proc parseJsonExtension( extension : string ) : seq[string] =
  #Parsing the elements from the "json/extensions.json" file ( >=1 values )
  var 
    list : seq[string] = @[]
  try : 
    let 
      element : string = jsonData[extension].get_str()
      validextension : int = len(jsonData[extension])

    if validextension == 0 : 
      add(list, element)
      return list
    
    else : 
      for i in countup(1, 9) : 
        var extension2 = extension & intToStr(i)
        try : 
          add(list, jsonData[extension][extension2].get_str())
        except : 
          discard 
  except : 
    discard

  return list

proc yaraRuleStructure( ext : string ) : string = 
  #[ Yara rule structure file. The "content" variable
  contains all the rule that will be written. ]#
  var 
    content : string = fmt"rule {ext}_rule " & '{' & '\n' & repeat(' ', 4) & "strings : " & '\n' 
    extensions : seq[string] = parseJsonExtension(ext)

  for i in 0..len(extensions) - 1 : 
    content &= repeat(' ', 8) & fmt"$s{i} = " & "{ " & extensions[i] & " }\n"
  content &= repeat(' ', 4) & "condition : any of them \n}"

  if len(extensions) == 0 : 
    content = ""  

  return content

proc main() : void =
  runShellCommand(fmt"nim c -r extensions.nim {argument}")
  
  for line in lines "files/extensions.txt" :
    #creating .yara files in "yara" directory
    extensionsInPath.add(line)
    writeFile(fmt"yara/{line}_rule.yara", yaraRuleStructure(line))

  for file in walkDir("yara") : 
    #removing the yara rules for non-existend extensions
    if len(readFile(file.path)) == 0 : 
      runShellCommand(fmt"rm {file.path}")   

  for i in 0..len(extensionsInPath) - 1 : 
    #removing all the non-existend extensions from the json file
    if len(parseJsonExtension(extensionsInPath[i])) == 0 : 
      extensionsInPath[i] = ""
  extensionsInPath = extensionsInPath.filterIt(it != "")

  #reading all the files from a path
  rules = filelist("yara")
  argFiles = filelist(argument) 

  #This is the scan of the file ( the output )
  for file in argFiles : 
    for rule in rules : 
      runShellCommand(fmt"yara {rule} {file} > files/positiverule.txt")
      let content : seq[string] = readFile("files/positiverule.txt").split().filterIt(it != "")
      
      for extention in extensionsInPath : 
        if content.len > 0 : 
          if ( contains(content[0], extention) and not contains(content[1], extention) ) or ( not contains(content[0], extention) and contains(content[1], extention) ) : 
            hasExtensionChanged(file)
        else : 
          if contains(rule, extention) and contains(file, extention) : 
            echo fmt"yara {rule} {file} > files/positiverule.txt"
            hasExtensionChanged(file)

main()