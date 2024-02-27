import asyncdispatch, os

var
  path : string = paramStr(1)
  files : seq[string]

for i in walkDir(path): 
  files.add(i.path)

func deleteByName( lst : seq[string], name : string ) : seq[string] = 
  var lst2 : seq[string]
  for i in countup(0, len(lst) - 1) :
    if lst[i] != name : lst2.add(lst[i])
  
  result = lst2

func seqDifference(lst1, lst2 : seq[string]) : seq[string] = 
  var 
    i, j : int
    l1 = lst1
    l2 = lst2

  if len(l1) > len(l2) : 
    var aux = l1
    l1 = l2
    l2 = aux

  var finalSeq : seq[string] = l2

  for i in countup(0, len(l2) - 1) :
    for j in countup(0, len(l1) - 1) :
      if l2[i] == l1[j] : finalSeq = deleteByName(finalSeq, l1[j])
  
  result = finalSeq

proc listen( location : string ) : Future[void] {.async.} = 
  var 
    files2 : seq[string]
  
  while true : 
    await sleepAsync(10)
    for file in walkDir(location) :
      files2.add(file.path)

    if len(seqDifference(files, files2)) > 0 : 
      echo seqDifference(files, files2)
      break

    setLen(files2, 0)

proc main() {.async.} = 
  await listen(path)

waitFor main()
