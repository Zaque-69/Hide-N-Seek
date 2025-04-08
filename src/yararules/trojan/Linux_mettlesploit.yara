rule Linux_mettlesploit_trojan_4eae9a20 {
    meta : 
		creation_date = "17/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "AD4D48D728C99A9DDBC84C3AD0061CABB9291A80EA864652F7335EE2860FE424"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/4eae9a20919d84e174430f6d33b4520832c9a05b4f111bb15c8443a18868c893"
        os = "Linux"

    strings : 

        // mettlesploit
        $b1 = { 6D 65 74 74 6C 65 73 70 6C 6F 69 74 }

        // /mettle/mettle/src/main.c
        $b2 = { 2F 6D 65 74 74 6C 65 2F 6D 65 74 74 6C 65 2F 73 72 63 2F 6D 61 69 6E 2E 63 }

    condition : 
        all of them
}