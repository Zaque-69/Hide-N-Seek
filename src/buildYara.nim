import json, times, strutils, std/strformat

let init : float =  cpuTime()


proc pass() = return

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

  var
    yaraStructure : string

  let fileContent = readFileContent("extensions.json")
  let jsonData = parseJson(fileContent)
  let hexDecimals = jsonData[extensionFile].getStr()

  if len(hexDecimals) > 0 : echo hexDecimals

  else : 
    for i in countup(1, 9) :
      try :
        let secondExtensionFile = extensionFile & intToStr(i)
        #                       byte(nr)      {     previsious text from file     endline     hex decimals from json (all from an extension)      }
        yaraStructure = "\n" & "byte" & intToStr(i) & " = {" & readFileContent("newww.txt") & jsonData[extensionFile][secondExtensionFile].getStr() & "}"

        #writeYara("newww.txt", yaraStructure)

        echo yaraStructure
        yaraStructure = ""


      except : pass()
      
main("pem")

echo cpuTime() - init
