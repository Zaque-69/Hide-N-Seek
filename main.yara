rule findExe{
  meta :
    description = "Z4que"

  strings:
    $mz_byte = "MZ"

  condition :
    $mz_byte at 0
}

rule findPng{
  meta :
    description = "Z4que"

  strings:
    $mz_byte = "PNG"
    
  condition :
    $mz_byte at 1
}
