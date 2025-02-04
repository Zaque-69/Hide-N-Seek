rule Linux_miner_3ff6b428 {
    meta : 
		creation_date = "28/12/2024"
        update_date = "03/02/2025"
        fingerprint = "C6C8C412443CAA4F9607AF0A17C03C63BEA084FCB9CD4FC0F624BA7D15E458E5"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // Don't expect high hashrates
        $b1 = { 44 6F 6E 27 74 20 65 78 70 65 63 74 20 68 69 67 68 20 68 61 73 68 72 61 74 65 73 }

        // You need to specify the coin that you want to mine
        $b2 = { 59 6F 75 20 6E 65 65 64 20 74 6F 20 73 70 65 63 69 66 79 20 74 68 65 20 63 6F 69 6E 20 74 68 61 74 20 79 6F 75 20 77 61 6E 74 20 74 6F 20 6D 69 6E 65 }

        // Unrecognised coin
        $b3 = { 55 6E 72 65 63 6F 67 6E 69 73 65 64 20 63 6F 69 6E }

    condition : 
        filesize > 2MB
        and all of them
}

rule Linux_miner_5c03ff30 { 
    meta : 
		creation_date = "11/01/2025"
        fingerprint = "772486CD7FAF27497CF57CA3916DC8794EEC8668F41A39E776FFCB4DB0691D14"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // coin is not valid
        $b1 = { 63 6F 69 6E 20 69 73 20 6E 6F 74 20 76 61 6C 69 64 }

    condition :  
        all of them
        and filesize > 2MB
}


rule Linux_miner_4c38654e { 
    meta : 
		creation_date = "17/01/2025"
        update_date = "28/01/2025"
        fingerprint = "EDF9E44BE81F87B1DF0F888FC39619A4D2A20F6A19A1E6D9C62D942E3FBDA577"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // vendor/golang.org/x/crypto/cryptobyte
        $b1 = { 76 65 6E 64 6F 72 2F 67 6F 6C 61 6E 67 2E 6F 72 67 2F 78 2F 63 72 79 70 74 6F 2F 63 72 79 70 74 6F 62 79 74 65 }

    condition :  
        filesize > 1MB
        and all of them
}
