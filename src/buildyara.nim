#[
  With the 'extensions.nim' file, we can check if a file have its extension changed
  based on each file signature. This code build a YARA rule for each extension from a dir.

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures
  Z4que 2024 - All rights reserved
]#

import 
  json, 
  os, 
  sequtils,
  strformat,
  strutils

from shell import 
  hasExtensionChanged,
  runShellCommand

from helpers import 
  fileList, 
  stringToSequence

# Parsing the elements from the "json/extensions.json" file ( >=1 values )
proc parseJsonExtension( extension : string ) : seq[string] =
  var 
    list : seq[string] = @[]
    jsonData = parse_json(readFile("json/extensions.json")) 

  try : 
    let 
      element : string = jsonData[extension].get_str()
      validextension : int = len(jsonData[extension])

    # If the extension have 1 header, we return the list
    if validextension == 0 : 
      add(list, element)
      return list
    
    # Else we get all the headers from the extension (ex : zip1, zip2, ...)
    else : 
      for i in countup(1, 9) : 
        var extension2 = extension & intToStr(i)
        add(list, jsonData[extension][extension2].get_str())
        
  except KeyError: 
    discard

  list

# Generate a rule by the extensions found, in the "yara" folder
proc createYaraRuleByExtension( ext : string ) : string = 
  var 
    content : string = fmt"rule {ext}_rule " & '{' & '\n' & repeat(' ', 4) & "strings : " & '\n' 
    extensions : seq[string] = parseJsonExtension(ext)

  for i in 0..len(extensions) - 1 : 
    content &= repeat(' ', 8) & fmt"        $s{i} = " & "{ " & extensions[i] & " }\n"
  content &= repeat(' ', 4) & "condition : any of them \n}"

  if len(extensions) == 0 : 
    content = ""  

  content

# Recursive function to find all the files with extensiosn changed in the path
proc checkExtensionChanged( path : string, rulesFound : seq[string], extensionsFound : seq[string] ) = 
  for file in walkDir(path) : 
    if file.kind == pcFile : 
      for rule in rulesFound : 
        
        # Calling the command to scan the files
        runShellCommand(fmt"yara {rule} {path} > File/positiverule.txt")
        let fileContent : string = readFile("File/positiverule.txt")
        let seqContent : seq[string] = stringToSequence(fileContent)
        
        for ext in extensionsFound : 
          if seqContent.len > 0 : 
            if ( contains(seqContent[0], ext) and not contains(seqContent[1], ext) ) or ( not contains(seqContent[0], ext) and contains(seqContent[1], ext) ) : 
              hasExtensionChanged(file.path)

          else : 
            if contains(rule, ext) and contains(file.path, ext) : 
              hasExtensionChanged(file.path)

    else : 
      checkExtensionChanged(file.path, rulesFound, extensionsFound)     

# The main procedure
proc main() =
  let  argument : string = paramStr(1) 
  var                        
    rules : seq[string] = fileList("yara")
    extensionsInPath : seq[string] = @[]

  runShellCommand(fmt"nim c -r extensions.nim {argument}")
  
  # Creating yara rules by the extensions found
  for line in lines "File/extensions.txt" :
    add(extensionsInPath, line)
    writeFile(fmt"yara/{line}_rule.yara", createYaraRuleByExtension(line))

  # Removing the yara rules for non-existend extensions
  for file in walkDir("yara") : 
    if len(readFile(file.path)) == 0 : 
      runShellCommand(fmt"rm {file.path}")   

  # Removing all the non-existend extensions from the json file
  for i in 0..len(extensionsInPath) - 1 : 
    if len(parseJsonExtension(extensionsInPath[i])) == 0 : 
      extensionsInPath[i] = ""
  extensionsInPath = extensionsInPath.filterIt(it != "")

  # Calling the recursive function
  checkExtensionChanged(argument, rules, extensionsInPath)

when isMainModule : 
  main()