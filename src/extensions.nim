import os

# Removing the duplicate extensions found
proc removeDouble( list : seq[string] ) : seq[string] =
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

# The main procedure
proc main() = 
  let argument : string = paramStr(1)
  var
    finalFiles : seq[string]
    extension : string 
    check : bool = false

  writeFile("File/extensions.txt", "")

  for file in walkDir(argument) :
    if file.kind == pcFile : 
      for character in file.path : 
        if character == '.' : 
          check = true

        if check : 
          extension &= character
      
      #adding extensions without dots
      if len(extension) > 0 : 
        add(finalFiles, extension[1..len(extension) - 1])
      
      check = false
      extension = ""

  finalFiles = removeDouble(finalFiles)

  for ext in finalFiles :
    writeFile("File/extensions.txt", readFile("File/extensions.txt") & ext & '\n')

when isMainModule :
  main()
