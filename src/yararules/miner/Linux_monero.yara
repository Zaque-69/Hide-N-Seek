rule Linux_monero_miner_ed5557ed {
    meta : 
		creation_date = "28/12/2024"
        update_date = "03/02/2025"
        fingerprint = "68EEEE68BD7795E9CCF56651DB93023B135CA68DABFFB838006E707FCA260A5B"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // cryptonight
        $b1 = { 63 72 79 70 74 6F 6E 69 67 68 74 }

        // cryptonight-monerov7
        $b2 = { 63 72 79 70 74 6F 6E 69 67 68 74 2D 6D 6F 6E 65 72 6F 76 37 } 

        // cryptonight-monerov8
        $b3 = { 63 72 79 70 74 6F 6E 69 67 68 74 2D 6D 6F 6E 65 72 6F 76 38 }
    
        // cryptonight_v7
        $b4 = { 63 72 79 70 74 6F 6E 69 67 68 74 5F 76 37 }

        // randomx
        $b5 = { 72 61 6E 64 6F 6D 78 }

        // RandomARQ
        $b6 = { 52 61 6E 64 6F 6D 41 52 51 }

        // monero.xmr.arqma.ravencoin.raven
        $b8 = { 6D 6F 6E 65 72 6F 00 78 6D 72 00 61 72 71 6D 61 00 72 61 76 65 6E 63 6F 69 6E 00 72 61 76 65 6E }

        // XMRIG
        $b9 = { 58 4D 52 49 47 }

    condition : 
        filesize > 1MB
        and 4 of ( $b* )  
}

rule Linux_monero_miner_1eb236 {
    meta : 
		creation_date = "09/01/2025"
        update_date = "03/02/2025"
        fingerprint = "898741CDBAD0896EC3FAF772A1AA97FC166221CA784D304311BCDDC83D310E14"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // .....A1...E........A.
        $b1 = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }

    condition : 
        all of them
        and filesize > 500KB
}

rule Linux_monero_miner_prometei {
    meta : 
		creation_date = "09/01/2025"
        update_date = "04/02/2025"
        fingerprint = "FED9765E4A10540694AACDA3A90E86DE33117D0AB8326228F112244A060004D6"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // cgi-bin/prometei.cgi
        $b1 = { 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

    condition : 
        all of them
}

rule Linux_monero_miner_0a79399c {
    meta : 
		creation_date = "09/01/2025"
        fingerprint = "F15CF1F8E03A67EA0C0B89A30DC96F5EABB7418FA75149252043896F41375304"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // xmrigMiner
        $b1 = { 78 6D 72 69 67 4D 69 6E 65 72 }

    condition : 
        all of them
}

rule Linux_monero_miner_1ce94d78 {
    meta : 
		creation_date = "04/02/2025"
        fingerprint = "B47263214E0D6349633CE413DEC75067E19B2EFD9005F4F47FB8743EE2245413"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // xmrig5Pools
        $b1 = { 78 6D 72 69 67 35 50 6F 6F 6C 73 }

    condition : 
        all of them
        and filesize > 700KB
}
