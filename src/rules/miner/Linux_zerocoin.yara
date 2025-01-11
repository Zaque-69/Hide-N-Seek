rule Linux_zerocoin_miner { 
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "E19347E2F12707B409ED9525A8EBD7879D9DD43874E5CF240C267C0C5632B3D9"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // Successfully minted a zerocoin
        $b1 = { 53 75 63 63 65 73 73 66 75 6C 6C 79 20 6D 69 6E 74 65 64 20 61 20 7A 65 72 6F 63 6F 69 6E }

    condition :  
        all of them
        and filesize > 1MB
}