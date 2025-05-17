rule Linux_gafgyt_trojan_8d5fa5a7 { 
    meta : 
	    creation_date = "28/12/2024"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "A89A3BCA46EB189D692EE251384EFB67F06A53FA688605033B621637D32AA3B6"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/8d5fa5a775f4fb0faf7d01d0553aadab4cebab91e53f933c83509b5b506779d3"
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
        update_date = "10/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "FF014274F142FA9F8F551AE6C202CE19D4DBBEC0C8D1D9EC6942E654805FCF25"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/3dcad97c6bc823158aa8de7ab177af8c430bb20acd1f9d4e12444c482d0edd1d"
        os = "Linux"

    strings : 

        // 4E/x31/x6B/x4B/x31/x20/x21/x73/x69/x20/x4D/x33/x75/x79/x20/x4C/x30/x56/x72/x33 -> N1kK1 !si M3uy L0Vr3 <3
        $b1 = { 34 45 2F 78 33 31 2F 78 36 42 2F 78 34 42 2F 78 33 31 2F 78 32 30 2F 78 32 31 2F 78 37 33 2F 78 36 39 2F 78 32 30 2F 78 34 44 2F 78 33 33 2F 78 37 35 2F 78 37 39 2F 78 32 30 2F 78 34 43 2F 78 33 30 2F 78 35 36 2F 78 37 32 2F 78 33 33 }

        // /x20/x3C/x33/x20/x50/x61/x32/x72/x43/x48/x20/x4D/x32/x20/x41/x34/x34/x72/x43/x4 -> Pa2rCH M2 A44rCK
        $b2 = { 2F 78 32 30 2F 78 33 43 2F 78 33 33 2F 78 32 30 2F 78 35 30 2F 78 36 31 2F 78 33 32 2F 78 37 32 2F 78 34 33 2F 78 34 38 2F 78 32 30 2F 78 34 44 2F 78 33 32 2F 78 32 30 2F 78 34 31 2F 78 33 34 2F 78 33 34 2F 78 37 32 2F 78 34 33 2F 78 34 }

    condition : 
        filesize > 75KB
        and filesize < 200KB
        and all of them
}

rule Linux_gafgyt_trojan_7d137848 {
    meta : 
        creation_date = "04/02/2025"
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "A3B57138D2D8FBD64586575CD4A0ECB94BA5FDA3E3A3B9D0A4EA08D417106221"
        sample = ""
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
        update_date = "04/04/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "C34224482EDD410D7E41ED5590FA7D2BA663282260F9DA17A88ACAC1283BE1E6"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/1fbfb2501ebe6e653d5e1e53b19f49eabbb34ed350615140097704539faacd0b"
        os = "Linux"
	
    strings : 

        // ..E......t..E.0....E..
        $b1 = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }

    condition : 
	    all of them
}
