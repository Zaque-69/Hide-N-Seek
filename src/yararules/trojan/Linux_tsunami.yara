rule Linux_tsunami_trojan_7a60c84f { 
    meta : 
		creation_date = "19/01/2025"
        fingerprint = "F815B359BCF5BE67181D5E0828035CF42E804336C0E734389DAC3DD2EC6D3B8D"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // NOTICE %s :Spoofs:
        $b1 = { 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A }

        // kill -9 %d
        $b2 = { 6B 69 6C 6C 20 2D 39 20 25 64 }

        // Gets the current spoofing
        $b3 = { 47 65 74 73 20 74 68 65 20 63 75 72 72 65 6E 74 20 73 70 6F 6F 66 69 6E 67 }

    condition : 
        all of them
}