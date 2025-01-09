rule Linux_miner {
    meta : 
		creation_date = "28/12/2024"
        update_date = "09.01.2025"
        fingerprint = "951DE0AD70883AFB6D4FA67E676E991F6423C7C64EBB9C2D95D140AF23F37AD1"
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
        any of ( $b* )
        and filesize > 2MB
}