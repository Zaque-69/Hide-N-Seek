rule _35308b8b770d2d4f78299262f595a0769e55152cb432d0efc42292db01609a18 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "1/11/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // The more you know... :)
        $b1 = { 54 68 65 20 6D 6F 72 65 20 79 6F 75 20 6B 6E 6F 77 2E 2E 2E 20 3A 29 }
        
        // Did you know that VV Cephei, also known as HD 208816,
        $b2 = { 44 69 64 20 79 6F 75 20 6B 6E 6F 77 20 74 68 61 74 20 56 56 20 43 65 70 68 65 69 2C 20 61 6C 73 6F 20 6B 6E 6F 77 6E 20 61 73 20 48 44 20 32 30 38 38 31 36 2C }
            
        //  is an eclipsing binary star system located in the constellation Cepheus,
        $b3 = { 20 69 73 20 61 6E 20 65 63 6C 69 70 73 69 6E 67 20 62 69 6E 61 72 79 20 73 74 61 72 20 73 79 73 74 65 6D 20 6C 6F 63 61 74 65 64 20 69 6E 20 74 68 65 20 63 6F 6E 73 74 65 6C 6C 61 74 69 6F 6E 20 43 65 70 68 65 75 73 2C }
        
        // , approximately 5,000 light years from Earth? It is both a B[e] star and shell star. Awesome!
        $b4 = { 2C 20 61 70 70 72 6F 78 69 6D 61 74 65 6C 79 20 35 2C 30 30 30 20 6C 69 67 68 74 20 79 65 61 72 73 20 66 72 6F 6D 20 45 61 72 74 68 3F 20 49 74 20 69 73 20 62 6F 74 68 20 61 20 42 5B 65 5D 20 73 74 61 72 20 61 6E 64 20 73 68 65 6C 6C 20 73 74 61 72 2E 20 41 77 65 73 6F 6D 65 21 }
        
        // https://en.wikipedia.org/wiki/VV_Cephei
        $b5 = { 68 74 74 70 73 3A 2F 2F 65 6E 2E 77 69 6B 69 70 65 64 69 61 2E 6F 72 67 2F 77 69 6B 69 2F 56 56 5F 43 65 70 68 65 69 }
        
        // /home/buildozer/aports/main/musl/src/musl-1.1.16
        $b6 = { 2F 68 6F 6D 65 2F 62 75 69 6C 64 6F 7A 65 72 2F 61 70 6F 72 74 73 2F 6D 61 69 6E 2F 6D 75 73 6C 2F 73 72 63 2F 6D 75 73 6C 2D 31 2E 31 2E 31 36 }
        
    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* ) 
        and filesize < 400KB
}