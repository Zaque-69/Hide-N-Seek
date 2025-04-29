rule Linux_tsunami_trojan_7a60c84f { 
    meta : 
		creation_date = "19/01/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "2A328F48E1FA6337F831B609D8DA41515CDDFF012BCAFCAFF3F78D76AFD43B47"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/7a60c84fb34b2b3cd7eed3ecd6e4a0414f92136af656ed7d4460b8694f2357a7"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F8C9FD68C21E3D6294F97F66A83F05623E6A5A4AC3D71E749B4B1F119998C8D2"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/d313859c242add69d6534f497a256607cf9611fadf06868a1e499c50556e3d3a"
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "86D3B2184827BBB5BC793F9388F95B21262E15B7E5EAF214938D261E4A19B446"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/38f52e34fe24e135b06a892db7864ab1921567d285e7f6aaa4c0e6b60e1f345e"
        os = "Linux"

    strings : 
        
        //  Already 'ning
        $b1 = { 20 41 6C 72 65 61 64 79 20 27 6E 69 6E 67 }

    condition : 
        filesize > 20KB
        and all of them
}

rule Linux_tsunami_trojan_6c6888a7 { 
    meta : 
		creation_date = "29/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "6B2972CDB1B35EC816C9DC6F551461F488E606DD5221CB3FA5FCB2FD57C8A563"
        sample = "https://bazaar.abuse.ch/download/6c6888a75d6a62dc7414dd22d0b6a70456a108a14889b8406f7aeb8b61b34633/"
        os = "Linux"

    strings : 
        
        //  I'm having a problem resolving my host
        $b1 = { 49 27 6D 20 68 61 76 69 6E 67 20 61 20 70 72 6F 62 6C 65 6D 20 72 65 73 6F 6C 76 69 6E 67 20 6D 79 20 68 6F 73 74 }

        // memory of David Bowie
        $b2 = { 6D 65 6D 6F 72 79 20 6F 66 20 44 61 76 69 64 20 42 6F 77 69 65 }

    condition : 
        filesize > 50KB
        and all of them
}