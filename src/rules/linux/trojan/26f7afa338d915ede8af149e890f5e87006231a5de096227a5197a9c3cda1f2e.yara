rule _26f7afa338d915ede8af149e890f5e87006231a5de096227a5197a9c3cda1f2e { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "27/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 157.245.83.214:4258
        $b1 = { 31 35 37 2E 32 34 35 2E 38 33 2E 32 31 34 3A 34 32 35 38 }

        // Scarface1337
        $b2 = { 53 63 61 72 66 61 63 65 31 33 33 37 }

        // /Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS
        $b3 = { 53 65 6C 66 20 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 20 61 6E 64 20 54 68 69 73 69 74 79 20 30 6E 20 55 72 20 46 75 43 6B 49 6E 47 20 46 6F 52 65 48 65 41 64 20 57 65 20 42 69 47 20 4C 33 33 54 20 48 61 78 45 72 53 0A }
   
        // /x38/xFJ/x93/xID/x9A
        $b4 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

    condition : 
        ( $header at 0 ) 
        and 3 of ( $b* )
        and filesize < 200KB
}