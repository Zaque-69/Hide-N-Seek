import json, times

let init : float =  cpuTime()

proc readFileContent(filename: string): string =
  var
    file: File
    content: string

  if open(file, filename) : content = readAll(file)

  close(file)
  return content

proc pass() = return

proc main( extensionFile : string) : void =
  let fileContent = readFileContent("extensions.json")

  if fileContent.len > 0:
    try:

      let jsonData = parseJson(fileContent)

      echo jsonData[extensionFile].getStr()

    except : pass()

main("iso")

echo cpuTime() - init
