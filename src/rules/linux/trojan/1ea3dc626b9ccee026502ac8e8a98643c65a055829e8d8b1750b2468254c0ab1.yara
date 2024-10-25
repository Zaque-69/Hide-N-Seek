rule _1ea3dc626b9ccee026502ac8e8a98643c65a055829e8d8b1750b2468254c0ab1 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "25/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // goongangrunsshit
        $b1 = { 67 6F 6F 6E 67 61 6E 67 72 75 6E 73 73 68 69 74 }

        // TSource Engine Query
        $b2 = { 54 53 6F 75 72 63 65 20 45 6E 67 69 6E 65 20 51 75 65 72 79 }

        // 45.14.224.26
        $b3 = { 34 35 2E 31 34 2E 32 32 34 2E 32 36 }
   
        // MINECRAFT
        $b4 = { 4D 49 4E 45 43 52 41 46 54 }

        // TERRARIA
        $b5 = { 54 45 52 52 41 52 49 41 }

        // /x38/xFJ/x93/xID/x9A
        $b6 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

        // $IP
        $b7 = { 24 49 50 }

    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* )
        and filesize < 100KB
}