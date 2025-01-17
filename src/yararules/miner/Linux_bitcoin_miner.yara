rule Linux_bitcoin_miner { 
    meta : 
		creation_date = "28/12/2024"
        update_date = "09/01/2025"
        fingerprint = "C9527DC047EED07AAE046F79CEDA09A791F8EDBE0925C66B9409D3B1E16BED62"
        github = "https://github.com/Zaque-69"
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