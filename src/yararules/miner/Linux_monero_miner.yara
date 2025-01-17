rule Linux_monero_miner {
    meta : 
		creation_date = "28/12/2024"
        update_date = "09/01/2025"
        fingerprint = "1783F4B095072137D760162064BACCAD4DBC6BA2BEC67905D56469D44466A855"
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
        4 of ( $b* ) 
        and filesize > 1MB
}

rule Linux_monero_miner_1eb236 {
    meta : 
		creation_date = "09/01/2025"
        fingerprint = "C4849A5270C978534BCC29882F5CFB26BB7D5F17480078E7B4B5F1E74656C3B9"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings :         
        $b1 = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }

    condition : 
        all of them
        and filesize > 500KB
}

rule Linux_monero_miner_prometei {
    meta : 
		creation_date = "09/01/2025"
        fingerprint = "3C54FB5D927067866B60CB86D5109E536E277373F2D5C1474EE4828B0635DA10"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // cgi-bin/prometei.cgi        
        $b1 = { 63 67 69 2D 62 69 6E 2F 70 72 6F 6D 65 74 65 69 2E 63 67 69 }

    condition : 
        all of them
}