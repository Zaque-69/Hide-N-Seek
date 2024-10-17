rule _0f09e9e976cb08a75e787514536b63f3ad89b8a66ff1fcaaef33c0c032f50827 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "16/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /Users/mmd/Downloads/minergate-app-mobile-lostmaster
        $b1 = { 2F 55 73 65 72 73 2F 6D 6D 64 2F 44 6F 77 6E 6C 6F 61 64 73 2F 6D 69
            6E 65 72 67 61 74 65 2D 61 70 70 2D 6D 6F 62 69 6C 65 2D 6C 6F 73 74 6D
            61 73 74 65 72 }

        // /app/src/main/jni/hash-extra-skein
        $b2 = { 2F 61 70 70 2F 73 72 63 2F 6D 61 69 6E 2F 6A 6E 69 2F 68 61 73 68 2D
            65 78 74 72 61 2D 73 6B 65 69 6E }
            
        // money
        $b3 = { 6D 6F 6E 65 79 }

    condition : 
        ( $header at 0 ) 
        and 3 of ( $b* ) 
        and filesize < 10000KB
}