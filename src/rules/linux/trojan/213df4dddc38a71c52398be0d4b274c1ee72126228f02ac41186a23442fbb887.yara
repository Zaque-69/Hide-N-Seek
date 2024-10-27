rule _213df4dddc38a71c52398be0d4b274c1ee72126228f02ac41186a23442fbb887 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "26/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // PROT_EXEC|PROT_WRITE failed
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 20 66 61 69 6C 65 64 }
        
        // http://upx.sf.net
        $b2 = { 68 74 74 70 3A 2F 2F 75 70 78 2E 73 66 2E 6E 65 74 }
            
        // http://www.billybobbot.com/crawler/   
        $b3 = { 68 74 74 70 3A 2F 2F 77 77 77 2E 62 69 6C 6C 79 62 6F 62 62 6F 74 2E 63 6F 6D 2F 63 72 61 77 6C 65 72 2F }
    
        // UPX 3.95 Copyright (C) 1996-2018 the UPX Team
        $b4 = { 55 50 58 20 33 2E 39 35 20 43 6F 70 79 72 69 67 68 74 20 28 43 29 20 31 39 39 36 2D 32 30 31 38 20 74 68 65 20 55 50 58 20 54 65 61 6D }

        // Ubuntu 9.3.0-17
        $b5 = { 55 62 75 6E 74 75 20 39 2E 33 2E 30 2D 31 37 }

    condition : 
        ( $header at 0 ) 
        and 4 of ( $b* ) 
        and filesize < 5000KB
}