#[
  What this code do?
  With the 'extensions.nim' file, we can check if a file have its extension changed
  based on each file signature. This code build a YARA rule for each extension from a dir.
  Z4que 2024 - All rights reserved

  list of signatures : https://en.wikipedia.org/wiki/List_of_file_signatures
]#

import json, strutils, os, strformat
from runCommand import runShellCommand, has_extension_changed

var
  json_data = parse_json(readFile("json/extensions.json"))
  arg_1 : string = paramStr(1)
  boolean : bool = false
  yara_rules_list : seq[string] = @[]
  files_path_list : seq[string] = @[]
  extensions_in_path : seq[string] = @[]

#[ returning the words from a positive YARA rule ]#
proc return_yara_result( file : string ) : seq[string] = 
  return readFile(file).split(' ')

#returning the files from a path
proc return_file_list( path : string ) : seq[string] =
  var list : seq[string] = @[] 
  for file in walkDir(path) : 
    add(list, file.path) 

  return list

#[
  parsing the elements from the "json/extensions.json" file 
  The returned list can get one or more values
]#
proc parse_json_ext( extension : string ) : seq[string] = 
  var  list : seq[string] = @[]
  try : 
    var element : string = json_data[extension].get_str()

    if len(json_data[extension]) == 0 : 
      add(list, element)
      return list
    
    else : 
      for i in countup(1, 9) : 
        var extension2 = extension & intToStr(i)
        try : 
          add(list, json_data[extension][extension2].get_str())
        except : discard 
  except : discard

  return list

#[
  Here we are making a yara rule structure file
  The "content" variable contains all the rule that will be written. In
  the declaration is the top of the rule, then the bytes and the final.
]#
proc yara_rule_structure( ext : string ) : string = 
  var 
    content : string = fmt"rule {ext}_rule " & '{' & '\n' & repeat(' ', 4) & "strings : " & '\n' 
    extensions : seq[string] = parse_json_ext(ext)
  
  for i in 0..len(extensions) - 1 : 
    content &= repeat(' ', 8) & fmt"$s{i} = " & "{ " & extensions[i] & " }\n"
  content &= repeat(' ', 4) & "condition : any of them \n}"

  if len(extensions) == 0 : 
    content = ""
    
  return content

#This is the main procedure, where almost all the functon are used
proc main() : void =
  runShellCommand(fmt"nim c -r extensions.nim {arg_1}")
  
  #creating .yara files in "yara" directory and adding the extensions to a sequence
  for line in lines "File/extensions.txt" :
    extensions_in_path.add(line)
    writeFile(fmt"yara/{line}_rule.yara", yara_rule_structure(line))

  #removing the yara rules for non-existend extension in "json/extensions.json"
  for file in walkDir("yara") : 
    if len(readFile(file.path)) == 0 : 
      runShellCommand(fmt"rm {file.path}")

  #reading all the files from a path
  yara_rules_list = return_file_list("yara")
  files_path_list = return_file_list(arg_1)

  #Showing the result
  for file in files_path_list : 
    for rule in yara_rules_list : 
      runShellCommand(fmt"yara {rule} {file} > File/positive_rule.txt")

      if ( len("File/positive_rule.txt") > 0 ) : 
        let words : seq[string] = return_yara_result("File/positive_rule.txt")
        if ( len(words) > 0 ) : 
          for ext in extensions_in_path : 
            if contains(words[0], ext) and contains(words[1], ext) : 
              boolean = true

    if boolean : has_extension_changed(file, false)
    else :  has_extension_changed(file, true)

    boolean = false

main()
