rule Linux_malxmr_miner_433d25d4 { 
    meta : 
		creation_date = "28/01/2025"
        update_date = "04/04/2025"
        fingerprint = "3C241B54A9BCEC0F18BE154C56D7B5F4AA9136BF700197A453CBE9B8F4602742"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/433d25d45026e1eb7cc3495279f7fb0c73981bfc92481bdb12f19625481507f4"
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