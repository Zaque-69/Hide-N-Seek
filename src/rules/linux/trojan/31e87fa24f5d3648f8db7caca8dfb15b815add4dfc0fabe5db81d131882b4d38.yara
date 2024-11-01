rule _31e87fa24f5d3648f8db7caca8dfb15b815add4dfc0fabe5db81d131882b4d38 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "29/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // 13.81.41.97:872
        $b1 = { 31 33 2E 38 31 2E 34 31 2E 39 37 3A 38 37 32 }

        // /x38/xFJ/x93/xID/x9A
        $b2 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

        // WYHRzp68omQcEaoW
        $b3 = { 57 59 48 52 7A 70 36 38 6F 6D 51 63 45 61 6F 57 }
   
        // a7pInUoLgx1CPFlGB5JF
        $b4 = { 61 37 70 49 6E 55 6F 4C 67 78 31 43 50 46 6C 47 42 35 4A 46 }

        // zwcfbtGDTDdfgrtWImROXhdn
        $b5 = { 7A 77 63 66 62 74 47 44 54 44 64 66 67 72 74 57 49 6D 52 4F 58 68 64 6E }

        // rm -rf /bin/netstat
        $b6 = { 72 6D 20 2D 72 66 20 2F 62 69 6E 2F 6E 65 74 73 74 61 74 } 

    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* )
        and filesize < 100KB
}