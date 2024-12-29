rule Linux_monero_miner {
    meta : 
		creation_date = "28/12/2024"
        fingerprint = "96188a11993ccb319bc2703ce4ff08223c4b253fae0ffe8eca9064dd997814b3"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
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
        ( $header at 0 ) 
        and 4 of ( $b* ) 
        and filesize > 1MB
}