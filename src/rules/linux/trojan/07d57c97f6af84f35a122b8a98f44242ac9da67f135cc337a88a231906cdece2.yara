rule _07d57c97f6af84f35a122b8a98f44242ac9da67f135cc337a88a231906cdece2 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "11/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        $loader = { 2F 6C 69 62 36 34 2F 6C 64 2D 6C 69 6E 75 78 2D 78 38 36 2D 36 34 }   
        
        //Wed Jan 6 13:26:04
        $b1 = { 57 65 64 20 4A 61 6E 20 36 20 31 33 3A 32 36 3A 30 34 }

        //EST 2010.2.6.18-164.11.1
        $b2 = { 45 53 54 20 32 30 31 30 00 32 2E 36 2E 31 38 2D 31 36 34 2E 31 31 2E 31 }
            
        //Diagnostic tool for public CVE-2010-3081 exploit
        $b3 = { 44 69 61 67 6E 6F 73 74 69 63 20 74 6F 6F 6C 20 66 6F 72 20 70 75 62 6C
            69 63 20 43 56 45 2D 32 30 31 30 2D 33 30 38 31 20 65 78 70 6C 6F 69 74 }
        
        //Your in-memory kernel HAS A BACKDOOR that may have been left
        $b4 = { 59 6F 75 72 20 69 6E 2D 6D 65 6D 6F 72 79 20 6B 65 72 6E 65 6C 20 48 41
            53 20 41 20 42 41 43 4B 44 4F 4F 52 20 74 68 61 74 20 6D 61 79 20 68 61 76
            65 20 62 65 65 6E 20 6C 65 66 74 }

        //Your system is free from the backdoors that would be left in memory
        $b5 = { 59 6F 75 72 20 73 79 73 74 65 6D 20 69 73 20 66 72 65 65 20 66 72 6F 6D
            20 74 68 65 20 62 61 63 6B 64 6F 6F 72 73 20 74 68 61 74 20 77 6F 75 6C 64
            20 62 65 20 6C 65 66 74 20 69 6E 20 6D 65 6D 6F 72 79 }

        //http://www.ksplice.com/uptrack/cve-2010-3081
        $b6 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 6B 73 70 6C 69 63 65 2E 63 6F 6D 2F 75
            70 74 72 61 63 6B 2F 63 76 65 2D 32 30 31 30 2D 33 30 38 31 }
   
    condition : 
        ( $header at 0 ) 
        and $loader 
        and 5 of ( $b* ) 
        and filesize < 300KB
}