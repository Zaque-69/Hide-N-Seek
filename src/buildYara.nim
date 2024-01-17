import json, times, strutils, std/strformat

let init : float =  cpuTime()

proc pass() = return
var
  yaraContent : string 
  yaraStructure : string
  list : array[10, string]


proc writeYara(filename: string, content: string) =
  var 
    file: File

  if open(file, filename, fmWrite) :
    write(file, content)
    close(file)

proc readFileContent(filename: string): string =
  var
    file: File
    content: string

  if open(file, filename) : content = readAll(file)

  close(file)
  return content

proc main( extensionFile : string) : void =
    
  let fileContent = readFileContent("extensions.json")
  let jsonData = parseJson(fileContent)
  let hexDecimals = jsonData[extensionFile].getStr()

  if len(hexDecimals) > 0 : list[0] = hexDecimals

  else : 
    for i in countup(0, 9) :
      try :
        let secondExtensionFile = extensionFile & intToStr(i)
        yaraStructure = readFileContent("newww.txt") & jsonData[extensionFile][secondExtensionFile].getStr()
        list[i] = yaraStructure
        yaraStructure = ""
        

      except : pass()

main("jpg")

proc buildYaraStructure(bytes : string, number : int) : void =
  yaraContent = "rule" & intToStr(number) & " = { \n strings : \n"
  for i in countup(0, 9): 
    if len(list[i]) > 0 : yaraContent &= "$byte" & intToStr(i) & " = {" & list[i] & "} \n"
  yaraContent &= "\n conditions : "
  for i in countup(0, 9): 
    if len(list[i]) > 0 : yaraContent &= "$byte" & intToStr(i) & " & "

  echo yaraContent

#
for i in countup(0, 9 mod 2):
  if len(list[i]) > 0 : 
    buildYaraStructure(list[0], i)

echo cpuTime() - init
