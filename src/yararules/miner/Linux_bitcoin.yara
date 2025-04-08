rule Linux_bitcoin_miner { 
    meta : 
		creation_date = "28/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "3769DE000F428AABCF3C622132F5F07213501A2CD4C7198329DECE1CB6148A2F"
        sample = ""
        os = "Linux"

    strings : 

        // bitcoin-core
        $b1 = { 62 69 74 63 6F 69 6E 2D 63 6F 72 65 }

        // /icons/bitcoin
        $b2 = { 2F 69 63 6F 6E 73 2F 62 69 74 63 6F 69 6E }
            
        // CWallet::GetDebit()
        $b3 = { 43 57 61 6C 6C 65 74 3A 3A 47 65 74 44 65 62 69 74 28 29 }

    condition :  
        2 of ( $b* ) 
}