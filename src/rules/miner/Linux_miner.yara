rule Linux_miner {
    meta : 
		creation_date = "28/12/2024"
        fingerprint = "8c61e57decdb804b2264a6dd5a748208174b9c14d98cd5bbfc9551cea780f801"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // Don't expect high hashrates
        $b1 = { 44 6F 6E 27 74 20 65 78 70 65 63 74 20 68 69 67 68 20 68 61 73 68 72 61 74 65 73 }

        // You need to specify the coin that you want to mine
        $b2 = { 59 6F 75 20 6E 65 65 64 20 74 6F 20 73 70 65 63 69 66 79 20 74 68 65 20 63 6F 69 6E 20 74 68 61 74 20 79 6F 75 20 77 61 6E 74 20 74 6F 20 6D 69 6E 65 }

        // Unrecognised coin
        $b3 = { 55 6E 72 65 63 6F 67 6E 69 73 65 64 20 63 6F 69 6E }

    condition : 
        ( $header at 0 )
        and any of ( $b* )
        and filesize > 2MB
}