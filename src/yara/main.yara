rule findExe{
  meta :
    description = "Z4que"

  strings:
    $mz_byte = "{89 50 4E 47}"

  condition :
    $mz_byte
}