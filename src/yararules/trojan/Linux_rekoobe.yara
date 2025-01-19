rule Linux_rekoobe_trojan_ccf42d51 { 
    meta : 
		creation_date = "29/01/2025"
        fingerprint = "B481FD4458523A25EF0F413CAFF2530AF2073C3852CED65DDE1F6343E95418E0"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // 66666666
        $hmac1 = { 36 36 36 36 36 36 36 36 }

        // \\\\\\\\
        $hmac2 = { 5C 5C 5C 5C 5C 5C 5C 5C }

    condition : 
        all of them
        and filesize > 500KB
}
