rule Linux_monero_miner_ed5557ed {
    meta : 
		creation_date = "28/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "8356670798D0D8F2B61ACD3D6F32F222D9D2D54B8A83D98EFDF542A8A5ACA998"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/ed5557ed8c1450c30212bcd9486f2696bd9fc3fb3091e23ef55eff755a063719"
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

rule Linux_monero_miner_1eb236fc {
    meta : 
		creation_date = "09/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "26EE8010F8C662C7773FA5DAE69166F0DDB4D2BA65BD1961D40FF2A3E5BA7E6B"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/1eb236fc4728d8048cbbb94dab2215e31877ec7b6533f3720cd2156bc9192d92"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "69B913AC773936D79377BB3B53ADDEDD3892A9FDAB1BF9152E649B3941962A9C"
        sample = ""
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "0456E481B92434E33A69341CDA13EB0A3E171DC98A7A2C1538BF4F59AC477637"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/0a79399c441fca30d20e79fdabdd23ae33f3e16bf9c012cd1492604a03e656bb"
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
        update_date = "10/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "51B95E36507565456C2EBA590D49A805F09B18C2F67C9E10AEF203D24DD61F98"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/1ce94d788d01ae70782084d5dd48844ecf03629c3aaacff7f4bc35e59d4aaf55"
        os = "Linux"

    strings : 

        // xmrig5Pools
        $b1 = { 78 6D 72 69 67 35 50 6F 6F 6C 73 }

    condition : 
        filesize > 700KB
        and all of them
}

rule Linux_monero_miner_99296550 {
    meta : 
		creation_date = "10/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "C14987F31964ADCE12A7C923737D6B6058BF5BCE1B196B88849CC93502C0F75A"
        sample = "https://bazaar.abuse.ch/download/99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7/"
        os = "Linux"

    strings : 
        
        // if ! sudo
        $s1 = { 69 66 20 21 20 73 75 64 6F }

        // WALLET_BASE
        $b1 = { 57 41 4C 4C 45 54 5F 42 41 53 45 }

        // ERROR: Wrong wallet
        $b2 = { 45 52 52 4F 52 3A 20 57 72 6F 6E 67 20 77 61 6C 6C 65 74 }

        // EXP_MONERO_HASHRATE
        $b3 = { 45 58 50 5F 4D 4F 4E 45 52 4F 5F 48 41 53 48 52 41 54 45 }

        // Mining in background 
        $b4 = { 4D 69 6E 69 6E 67 20 69 6E 20 62 61 63 6B 67 72 6F 75 6E 64 }

        // c3pool_miner.service
        $b5 = { 63 33 70 6F 6F 6C 5F 6D 69 6E 65 72 2E 73 65 72 76 69 63 65 }

    condition : 
        filesize > 10KB
        and filesize < 20KB
        and all of ( $s* )
        and 3 of ( $b* )
}