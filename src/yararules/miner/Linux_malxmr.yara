rule Linux_malxmr_miner_433d25d4 { 
    meta : 
		creation_date = "28/01/2025"
        fingerprint = "351E07AF960A1DD0E3F8C2A0936E4BF056C9E9EE4A534FE938625553EFF43814"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // PID
        $b1 = { 50 49 44 }

        // Addr:
        $b2 = { 41 64 64 72 3A }

        // inotify
        $b3 = { 69 6E 6F 74 69 66 79 }

    condition :  
        all of them
}