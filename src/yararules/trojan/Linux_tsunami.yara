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

rule Linux_tsunami_trojan_d313859c { 
    meta : 
		creation_date = "02/02/2025"
        fingerprint = "5C16A02E52D6BB8E49806BD2EE8CE26257888E455C010BB47FA459171F5BA84F"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // Attacking
        $b1 = { 41 74 74 61 63 6B 69 6E 67 }

        // Tsunami heading for
        $b2 = { 54 73 75 6E 61 6D 69 20 68 65 61 64 69 6E 67 20 66 6F 72 }

        // Killing PID
        $b3 = { 4B 69 6C 6C 69 6E 67 20 50 49 44 }

    condition : 
        all of them
}

rule Linux_tsunami_trojan_38f52e34 { 
    meta : 
		creation_date = "03/02/2025"
        fingerprint = "F7BAE25C4D52E14C772DE1AF0AC57691624255E2BDF832B78594947DCB777395"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        //  Already 'ning
        $b1 = { 20 41 6C 72 65 61 64 79 20 27 6E 69 6E 67 }

    condition : 
        all of them
}