rule _2d184ccea6eb9ea1e828b75a2f542b4f032a6b789dc15d25542f79edd8a06c3a { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "27/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 45.141.58.75:839
        $b1 = { 34 35 2E 31 34 31 2E 35 38 2E 37 35 3A 38 33 39 00 }

        // TSource Engine Query
        $b2 = { 54 53 6F 75 72 63 65 20 45 6E 67 69 6E 65 20 51 75 65 72 79 }

    condition : 
        ( $header at 0 ) 
        and 2 of ( $b* )
        and filesize < 200KB
}