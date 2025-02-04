rule Linux_gafgyt_trojan_8d5fa5a7 { 
    meta : 
	    creation_date = "28/12/2024"
        update_date = "03/02/2025"
        fingerprint = "8C375FE32A73D54E1749A61B3672F2F68D513ECE6588EEE47D486A7EA7144A3E"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        
        // WANPPPConnection:1
        $b1 = { 57 41 4E 50 50 50 43 6F 6E 6E 65 63 74 69 6F 6E 3A 31 }

        // HuaweiHomeGateway
        $b2 = { 48 75 61 77 65 69 48 6F 6D 65 47 61 74 65 77 61 79 }
            
        // www.google.com
        $b3 = { 77 77 77 06 67 6F 6F 67 6C 65 03 63 6F 6D }
        
    condition :
        filesize < 1MB 
        and all of them
}

rule Linux_gafgyt_trojan_3dcad97c { 
    meta : 
	    creation_date = "11/01/2025"
        fingerprint = "FF6A569D2A38DC79D1B709FE19DCCCED043900D295C48E1D6F0316090C97E333"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 

        // 4E/x31/x6B/x4B/x31/x20/x21/x73/x69/x20/x4D/x33/x75/x79/x20/x4C/x30/x56/x72/x33 -> N1kK1 !si M3uy L0Vr3 <3
        $b1 = { 34 45 2F 78 33 31 2F 78 36 42 2F 78 34 42 2F 78 33 31 2F 78 32 30 2F 78 32 31 2F 78 37 33 2F 78 36 39 2F 78 32 30 2F 78 34 44 2F 78 33 33 2F 78 37 35 2F 78 37 39 2F 78 32 30 2F 78 34 43 2F 78 33 30 2F 78 35 36 2F 78 37 32 2F 78 33 33 }

        // /x20/x3C/x33/x20/x50/x61/x32/x72/x43/x48/x20/x4D/x32/x20/x41/x34/x34/x72/x43/x4 -> Pa2rCH M2 A44rCK
        $b2 = { 2F 78 32 30 2F 78 33 43 2F 78 33 33 2F 78 32 30 2F 78 35 30 2F 78 36 31 2F 78 33 32 2F 78 37 32 2F 78 34 33 2F 78 34 38 2F 78 32 30 2F 78 34 44 2F 78 33 32 2F 78 32 30 2F 78 34 31 2F 78 33 34 2F 78 33 34 2F 78 37 32 2F 78 34 33 2F 78 34 }

    condition : 
        all of them
}

rule Linux_gafgyt_trojan_4a192a22 {
    meta : 
        creation_date = "16/01/2025"
        update_date = "28/01/2025"
        fingerprint = "EFA3E52672729D91CD3E80AC244FAC8FCF731671A4C6853E6B03E6BF53E58097"
        github = "https://github.com/Zaque-69"
        os = "Linux"
	
    strings : 

        // PROT_EXEC
        $b1 = { 50 52 4F 54 5F 45 58 45 }

        // PROT_WRITE
        $b2 = { 50 52 4F 54 5F 57 52 49 54 45 }

        // failed
        $b3 = { 66 61 69 6C 65 64 }

        // proc/self/exe
        $b4 = { 70 72 6F 63 2F 73 65 6C 66 2F 65 78 65 }

    condition : 
	    all of them
}

rule Linux_gafgyt_trojan_7d137848 {
    meta : 
        creation_date = "04/02/2025"
        fingerprint = "C28764E2964D9A64EC172CF1887F77C206376F395D25C41AD5DF33CE1B0E3235"
        github = "https://github.com/Zaque-69"
        os = "Linux"
	
    strings : 

        // /x38/xFJ/x93/xID/x9A
        $b1 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

    condition : 
	    all of them
}

rule Linux_gafgyt_trojan_1fbfb250 {
    meta : 
        creation_date = "04/02/2025"
        fingerprint = "A08B24F2193953030A7745A7D8EBF2D26E1F70384FA1E7D34090172A56FE5B38"
        github = "https://github.com/Zaque-69"
        os = "Linux"
	
    strings : 

        // ..E......t..E.0....E..
        $b1 = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }

    condition : 
	    all of them
}
