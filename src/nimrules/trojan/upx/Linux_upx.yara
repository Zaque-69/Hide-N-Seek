rule Linux_miner_upx { 
    meta : 
		creation_date = "03/02/2024"
        fingerprint = ""
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // PROT_EXEC|PROT_WRITE failed
        $b1 = { 50 52 4F 54 5F 45 58 45 43 7C 50 52 4F 54 5F 57 52 49 54 45 20 66 61 69 6C 65 64 }

        // HOSTNAME
        $b2 = { 48 4F 53 54 4E 41 4D 45 }

        // 1996-
        $b3 = { 31 39 39 36 2D }

        //  UPX Team
        $b4 = { 20 55 50 58 20 54 65 61 6D }

    condition :  
        3 of ( $b* )
}