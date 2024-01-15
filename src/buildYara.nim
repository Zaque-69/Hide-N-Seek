import json

proc readFile(filename: string): string =
  var
    file: File
    content: string
  content = readAll(file)
  close(file)
  return content

proc pass() = return

proc main( fileExtension : string) =
  let fileContent = readFile("extensions.json")

  if fileContent.len > 0:
    try:
      let jsonData = parseJson(fileContent)

      let extension = jsonData[fileExtension].getStr()

    except : pass()
