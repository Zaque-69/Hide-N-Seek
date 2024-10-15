rule _0a79399c441fca30d20e79fdabdd23ae33f3e16bf9c012cd1492604a03e656bb { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "14/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /dev/null./proc/self/exe
        $b1 = { 2F 64 65 76 2F 6E 75 6C 6C 00 2F 70 72 6F 63 2F 73 65 6C 66 2F 65 78 65 }
        
        // Alpine 9.3.0
        $b2 = { 41 6C 70 69 6E 65 20 39 2E 33 2E 30 }
            
    condition : 
        ( $header at 0 ) 
        and 2 of ( $b* ) 
        and filesize < 200KB
}