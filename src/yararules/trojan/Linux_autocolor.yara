rule Linux_autocolor_trojan_270fc720 { 
    meta : 
		creation_date = "08/04/2024"
        github = "https://github.com/Zaque-69"
        fingerprint = "25E091EA9BCBD7F50115D4FF4C7257CE3C275AFD9B90B3BC0CC9083E9D5A44E1"
        sample = "https://bazaar.abuse.ch/download/270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43/"
        os = "Linux"

    strings : 

        // auto-color
        $b1 = { 61 75 74 6F 2D 63 6F 6C 6F 72 }

        // Timer
        $b2 = { 54 69 6D 65 72 }

        // %s/auto-color.-flush
        $b3 = { 25 73 2F 61 75 74 6F 2D 63 6F 6C 6F 72 00 2D 66 6C 75 73 68 }

        // preloH3T
        $b4 = { 70 72 65 6C 6F 48 33 54 }

        //  #install
        $o = { 23 69 6E 73 74 61 6C 6C }

    condition : 
        filesize > 150KB
        and filesize < 500KB
        and ( $o or true )
        and all of them
}