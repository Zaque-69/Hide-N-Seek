rule Linux_rekoobe_trojan_d0a3421d { 
    meta : 
		creation_date = "03/02/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "9D71886D58A4870B56430AEB4034D20740F6E10694FD092E7BA0F620FAD1FCE0"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/d0a3421d977bcce8e867ec10e4790aa4b69353edf9d5ddfc3dd0480a18878a19"
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
