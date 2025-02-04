rule Linux_rekoobe_trojan_d0a3421d { 
    meta : 
		creation_date = "03/02/2025"
        fingerprint = "D90D9EE22E2541339CA3E7EBB58323A994E3245F32B20CF2563EAFC4CD27E3E1"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // Usage: %s
        $b1 = { 55 73 61 67 65 3A 20 25 73 }

        // [ -p port ]
        $b2 = { 5B 20 2D 70 20 70 6F 72 74 20 5D }

        // listen.accept
        $b3 = { 6C 69 73 74 65 6E 00 61 63 63 65 70 74 }

    condition : 
        all of them
}

