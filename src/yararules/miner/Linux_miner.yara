rule Linux_miner_3ff6b428 {
    meta : 
		creation_date = "28/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "5983F39960604FFE7EC05829A16AF74834024FB9588C4DD40575F87AE3ED6629"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/3ff6b4287e49a01724626a9e11adceee7a478aa5e5778ec139a3f9011a02f3af"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F379A9339C56B9B7CCDE55F6FDC64DF167465888F7AB5AFC30AB7EC1857B3896"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/5c03ff30ccffc9d36c342510c7469682d3c411654ec52b0930d37a6c6aab9f72"
        os = "Linux"

    strings : 

        // coin is not valid
        $b1 = { 63 6F 69 6E 20 69 73 20 6E 6F 74 20 76 61 6C 69 64 }

    condition :  
        filesize > 2MB
        and all of them
}

rule Linux_miner_4c38654e { 
    meta : 
		creation_date = "17/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F71E2A8900E440C9129AA6829E2C38B50DCAA27D6FA5A758BC58B8543760F697"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/4c38654e08bd8d4c2211c5f0be417a77759bf945b0de45eb3581a2beb9226a29"
        os = "Linux"

    strings : 

        // vendor/golang.org/x/crypto/cryptobyte
        $b1 = { 76 65 6E 64 6F 72 2F 67 6F 6C 61 6E 67 2E 6F 72 67 2F 78 2F 63 72 79 70 74 6F 2F 63 72 79 70 74 6F 62 79 74 65 }

    condition :  
        filesize > 1MB
        and all of them
}
