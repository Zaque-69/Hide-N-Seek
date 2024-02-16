# os -> 'walkDir()', strutils -> paramStr(1)      
import os, strutils, sequtils
#import std/[os]

proc remDub( list : seq[string] ) : seq[string] =
  var
     finalList : seq[string]
     boolrean : bool = true

  for i in countup(0, len(list) - 1) :
     for j in countup(0, len(finalList) - 1) :
       if list[i] == finalList[j] : 
         boolrean = false
    
     if boolrean : 
       if len(list[i]) > 0 : finalList.add(list[i])
     boolrean = true

  return finalList



var
  files : seq[string]
  finalFiles : seq[string]
  extension : string 
  aux : string = ""
  boolrean : bool = false

for file in walkDir(paramStr(1)) :
  files.add(file.path)

#removing duplicate files

for file in files :
  for character in file : 
    if character == '.' : 
      boolrean = true

    if boolrean : 
      extension &= character
  
  #adding extensions without dots
  try : 
    finalFiles.add(extension[1..len(extension) - 1])
  except : 
    discard

  boolrean = false
  extension = ""

finalFiles = remDub(finalFiles)

for ext in finalFiles :
  writeFile("Files/extensions.txt", readFile("Files/extensions.txt") & ext & '\n')
