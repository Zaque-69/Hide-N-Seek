rule Linux_moobot_trojan_abuse_ch { 
    meta : 
		creation_date = "23/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "323C70B23B64779583EEAF0328BD7F8E643ED49D4B747858CEFC43C8F2CA3F81"
        sample = "https://github.com/MalwareSamples/Linux-Malware-Samples/blob/main/476a61b3829902f6b00fa9a80e555e55deb251d91989f9032a59cccdc08b9779"
        os = "Linux"

    strings : 
        
        // 255.255.255.255:1900
        $b1 = { 32 35 35 2E 32 35 35 2E 32 35 35 2E 32 35 35 3A 31 39 30 30 }

        // MAN: "ssdp:discover"
        $b2 = { 4D 41 4E 3A 20 22 73 73 64 70 3A 64 69 73 63 6F 76 65 72 22 }

        // urn:dial-multiscreen-org
        $b3 = { 75 72 6E 3A 64 69 61 6C 2D 6D 75 6C 74 69 73 63 72 65 65 6E 2D 6F 72 67 }

		// /x38/xFJ/x93/xID/x9A
        $b4 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

		// www.google.com
        $b5 = { 77 77 77 06 67 6F 6F 67 6C 65 03 63 6F 6D }

		// TeamSpeak
        $b6 = { 54 65 61 6D 53 70 65 61 6B }

		// Too many linksBroken
        $b7 = { 54 6F 6F 20 6D 61 6E 79 20 6C 69 6E 6B 73 00 42 72 6F 6B 65 6E }
		
		// Not a XENIX
        $b8 = { 4E 6F 74 20 61 20 58 45 4E 49 58 }
		
		// nickname
        $b9 = { 6E 69 63 6B 6E 61 6D 65 }
		
		// nginx
        $b10 = { 6E 67 69 6E 78 }
		
    condition : 
        7 of ( $b* )
		and filesize > 50KB
}
