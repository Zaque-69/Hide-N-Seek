rule _0a4b417193f63a3cce4550e363548384eb007f89e89eb831cf1b7f5ddf230a51 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /var/tmp/./dev/s
        $b1 = { 2F 76 61 72 2F 74 6D 70 2F 00 2F 64 65 76 2F 73 }
        
        // /usr/b./perl
        $b2 = { 2F 75 73 72 2F 62 D2 2F 70 65 72 6C }
            
        // /proc/self/exe
        $b3 = { 2F 70 72 6F 63 2F 73 65 6C 66 2F 65 78 65 }
   
    condition : 
        ( $header at 0 ) 
        and 2 of ( $b* ) 
        and filesize < 100KB
}