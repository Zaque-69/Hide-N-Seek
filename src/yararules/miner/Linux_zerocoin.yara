rule Linux_zerocoin_miner { 
    meta : 
		creation_date = "11/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "4921428889733E5DEBF1836C687CA1931718757FE1E72AF35C08FEAE4E469ACE"
        sample = ""
        os = "Linux"

    strings : 

        // Successfully minted a zerocoin
        $b1 = { 53 75 63 63 65 73 73 66 75 6C 6C 79 20 6D 69 6E 74 65 64 20 61 20 7A 65 72 6F 63 6F 69 6E }

    condition :
        filesize > 1MB  
        and all of them
}