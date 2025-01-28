rule Linux_rekoobe_trojan_ccf42d51 { 
    meta : 
		creation_date = "19/01/2025"
        update_date = "28/01/2025"
        fingerprint = "19C2F916C89155F5051E5371EB0B1C7B3D2A78477829F7DB8E9011230CA856AA"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // 66666666
        $hmac1 = { 36 36 36 36 36 36 36 36 }

        // \\\\\\\\
        $hmac2 = { 5C 5C 5C 5C 5C 5C 5C 5C }

    condition : 
        filesize > 500KB
        and all of them
}
