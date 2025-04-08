rule Linux_sshdoor_trojan_6de1e587 {
    meta : 
		creation_date = "18/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "91CEAA0EA6680E9994E5A96F649D8FC4AEF7F06BA2382A03C4193C9DE1C34BEF"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/6de1e587ac4aa49273042ffb3cdce5b92b86c31c9f85ca48dae8a38243515f75"
        os = "Linux"

    strings : 

        // SSH_KEY_BITS_RESERVED
        $b1 = { 53 53 48 5F 4B 45 59 5F 42 49 54 53 5F 52 45 53 45 52 56 45 44 }

        // attack detected
        $b2 = { 61 74 74 61 63 6B 20 64 65 74 65 63 74 65 64 }

        // backdoor
        $b3 = { 62 61 63 6B 64 6F 6F 72 }

        // hmac-ripemd160@openssh.com
        $b4 = { 68 6D 61 63 2D 72 69 70 65 6D 64 31 36 30 40 6F 70 65 6E 73 73 68 2E 63 6F 6D }

    condition : 
        all of them
}