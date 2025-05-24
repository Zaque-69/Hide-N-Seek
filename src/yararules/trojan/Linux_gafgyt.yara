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

rule Linux_gafgyt_trojan_1fbfb250 {
    meta : 
        creation_date = "04/02/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "86DA5C78C8FA02422FCEBC40544C502907A42F941FFFA01F9BBCB09DABCC4F82"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/1fbfb2501ebe6e653d5e1e53b19f49eabbb34ed350615140097704539faacd0b"
        os = "Linux"
	
    strings : 

        // ..E......t..E.0....E..
        $b1 = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }

    condition : 
	    all of them
}

rule Linux_gafgyt_trojan_Yakuza_FBI {
    meta : 
        creation_date = "23/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "113EEA29299559485E88C8DEA0241B843931729ED93D211E8AEE21922501924E"
        sample = "https://bazaar.abuse.ch/download/dc4344e3b495c0edf428772b93de873ad7d714a139d53efb277f0aa4a82be3eb"
        os = "Linux"
	
    strings : 

        // nameserver 8.8.4.4
        $b1 = { 6E 61 6D 65 73 65 72 76 65 72 20 38 2E 38 2E 34 2E 34 }

        // RSTFINACKPSH
        $b2 = { 52 53 54 00 46 49 4E 00 41 43 4B 00 50 53 48 }

        // 4E/x31/x6B/x4B
        $b3 = { 34 45 2F 78 33 31 2F 78 36 42 2F 78 34 42 }

        // chk_captcha
        $b4 = { 63 68 6B 5F 63 61 70 74 63 68 61 }

        // TLSBLACKNURSE
        $b5 = { 54 4C 53 00 42 4C 41 43 4B 4E 55 52 53 45 }

        // ICMP SCANNER
        $b6 = { 49 43 4D 50 00 53 43 41 4E 4E 45 52 }

        // ON OFF CHOOPA
        $b7 = { 4F 4E 00 4F 46 46 00 43 48 4F 4F 50 41 }

        // Wrong medium
        $b8 = { 57 72 6F 6E 67 20 6D 65 64 69 75 6D }

        // OVHRAW JUNK
        $b9 = { 4F 56 48 52 41 57 00 4A 55 4E 4B }

        // UDPRAW SHIT
        $b10 = { 55 44 50 52 41 57 00 53 48 49 54 }

        // GAME-KILLER XMAS
        $b11 = { 47 41 4D 45 2D 4B 49 4C 4C 45 52 00 58 4D 41 53 }

        // Killed %d
        $b12 = { 4B 69 6C 6C 65 64 20 25 64 }

        // www.thesubot
        $b13 = { 77 77 77 2E 74 68 65 73 75 62 6F 74 }

        // www.billybobbot.com/crawler
        $b14 = { 77 77 77 2E 62 69 6C 6C 79 62 6F 62 62 6F 74 2E 63 6F 6D 2F 63 72 61 77 6C 65 72 }

        // Rep Fucking NeTiS
        $b15 = { 52 65 70 20 46 75 63 6B 69 6E 67 20 4E 65 54 69 53 }

        // Thisity 0n 
        $b16 = { 54 68 69 73 69 74 79 20 30 6E }

        // Ur FuCkInG FoReHeAd
        $b17 = { 55 72 20 46 75 43 6B 49 6E 47 20 46 6F 52 65 48 65 41 64 }

        // We BiG L33T HaxErS
        $b18 = { 57 65 20 42 69 47 20 4C 33 33 54 20 48 61 78 45 72 53 }

		// YakuzaBotnet
        $m1 = { 59 61 6B 75 7A 61 42 6F 74 6E 65 74 }
		
        // Scarface1337Self
        $m2 = { 53 63 61 72 66 61 63 65 31 33 33 37 53 65 6C 66 }

    condition : 
	    all of ( $m* )
		and 12 of ( $b* )
		and filesize > 50KB
		and filesize < 150KB
}