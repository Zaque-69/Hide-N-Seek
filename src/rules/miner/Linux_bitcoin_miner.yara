rule Linux_bitcoin_miner { 
    meta : 
		creation_date = "28/12/2024"
        fingerprint = "310b360a0e99ff689ea256384a65eb6abdab5c7400e40b31950c06c2a3bd8109"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // bitcoin-core
        $b1 = { 62 69 74 63 6F 69 6E 2D 63 6F 72 65 }

        // /icons/bitcoin
        $b2 = { 2F 69 63 6F 6E 73 2F 62 69 74 63 6F 69 6E }
            
        // CWallet::GetDebit()
        $b3 = { 43 57 61 6C 6C 65 74 3A 3A 47 65 74 44 65 62 69 74 28 29 }

    condition : 
        ( $header at 0 ) 
        and 2 of ( $b* ) 
}