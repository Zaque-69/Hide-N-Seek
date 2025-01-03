import 
    strformat

# Extracting a header made of 4 characters ( comparing with '.ELF' from Linux ) 
proc extractHeaderFile(filename : string) : string =
    var 
        filecontent = open(filename)
        line : string = filecontent.readLine()

    try : 
        line[0..4]
    except : 
        ""

# Converting the ASCII values of the characters into Hex codes 
proc asciiToHex(header: string): string =
    var hex : string = ""
    for c in header : 
        hex &= fmt"{ord(c):X}"

    hex 

# Checkinf if the file have a Linux executable header
proc checkHeaderELF * (filename : string) : bool = 
    let
        header : string = extractHeaderFile(filename)
        hex_header : string = asciiToHex(header)

    if hex_header == "7F454C462" : 
        return true 

    false