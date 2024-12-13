rule PowerPoint_positive {
    meta : 
       author = "Z4que - All rights reverved"
	  date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

            // fucked-up-shit
        	$a1 = { 66 75 63 6B 65 64 2D 75 70 2D 73 68 69 74 }

            // sqlhost.dllw
        	$a2 = { 73 71 6C 68 6F 73 74 2E 64 6C 6C }

            // SeShutdownPrivilege
        	$a3 = { 53 65 53 68 75 74 64 6F 77 6E 50 72 69 76 69 6C 65 67 65 }
        
            // \sys3.exe
        	$a4 = { 5C 73 79 73 33 2E 65 78 65 }

            // \systm.txt
            $a5 = { 5C 73 79 73 74 6D 2E 74 78 74 }

    condition : 
        ( $header at 0 ) 
        and 1 of ( $a* ) 
}