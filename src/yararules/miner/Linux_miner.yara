rule Linux_miner {
    meta : 
		creation_date = "28/12/2024"
        update_date = "09.01.2025"
        fingerprint = "951DE0AD70883AFB6D4FA67E676E991F6423C7C64EBB9C2D95D140AF23F37AD1"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // Don't expect high hashrates
        $b1 = { 44 6F 6E 27 74 20 65 78 70 65 63 74 20 68 69 67 68 20 68 61 73 68 72 61 74 65 73 }

        // You need to specify the coin that you want to mine
        $b2 = { 59 6F 75 20 6E 65 65 64 20 74 6F 20 73 70 65 63 69 66 79 20 74 68 65 20 63 6F 69 6E 20 74 68 61 74 20 79 6F 75 20 77 61 6E 74 20 74 6F 20 6D 69 6E 65 }

        // Unrecognised coin
        $b3 = { 55 6E 72 65 63 6F 67 6E 69 73 65 64 20 63 6F 69 6E }

    condition : 
        any of ( $b* )
        and filesize > 2MB
}

rule Linux_miner_c968b1bd { 
    meta : 
		creation_date = "11/01/2024"
        fingerprint = "3F3E8B4F7D43570C3DE4DD3677CFD2492A915E95BD7A6CAAEF609E9843257FCA"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // PROT_EXEC|PROT_WRITE failed
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 20 66 61 69 6C 65 64 }

        // HOSTNAME
        $b2 = { 48 4F 53 54 4E 41 4D 45 }

        // 1996-2020 the UPX Team
        $b3 = { 31 39 39 36 2D 32 30 32 30 20 74 68 65 20 55 50 58 20 54 65 61 6D }

    condition :  
        all of them
        and filesize > 500KB
}

rule Linux_miner_5c03ff30 { 
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "772486CD7FAF27497CF57CA3916DC8794EEC8668F41A39E776FFCB4DB0691D14"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // coin is not valid
        $b1 = { 63 6F 69 6E 20 69 73 20 6E 6F 74 20 76 61 6C 69 64 }

    condition :  
        all of them
        and filesize > 2MB
}


rule Linux_miner_4c38654e { 
    meta : 
		creation_date = "17/01/2025"
        fingerprint = "844E9C4FD4C06E477EEFB0A1FB52AC5130F67AB08B3EDEDCA476928471B3CFE2"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // vendor/golang.org/x/crypto/cryptobyte
        $b1 = { 76 65 6E 64 6F 72 2F 67 6F 6C 61 6E 67 2E 6F 72 67 2F 78 2F 63 72 79 70 74 6F 2F 63 72 79 70 74 6F 62 79 74 65 }

    condition :  
        all of them
        and filesize > 1MB
}
