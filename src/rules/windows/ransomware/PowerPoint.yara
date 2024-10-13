rule PowerPoint_positive {
    meta : 
       author = "Z4que - All rights reverved"
	  date = "7/03/2024"

    strings : 
        $header = { 4D 5A }

        	$c1 = "sys3.exe" ascii wide
        	$c2 = "fucked-up-shit" ascii wide

        	$c3 = { 73 71 6C 68 6F 73 74 2E 64 6C 6C 00 53 65 53 68 75
         	        74 64 6F 77 6E 50 72 69 76 69 6C 65 67 65 }
        
        	$c4 = { 68 74 74 70 3A 2F 2F 00 52 4C }

    condition : 
        ( $header at 0 ) 
        and all of ( $c* ) 
}