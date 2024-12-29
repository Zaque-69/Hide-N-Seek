rule Linux_gafgyt_trojan { 
    meta : 
		creation_date = "28/12/2024"
        fingerprint = "7642fcfce0e684bd0d7e98c4bbd37d94f8c653f89a00752b0b0d6a2ca1f94b64"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // WANPPPConnection:1
        $b1 = { 57 41 4E 50 50 50 43 6F 6E 6E 65 63 74 69 6F 6E 3A 31 }

        // HuaweiHomeGateway
        $b2 = { 48 75 61 77 65 69 48 6F 6D 65 47 61 74 65 77 61 79 }
            
        // www.google.com
        $b3 = { 77 77 77 06 67 6F 6F 67 6C 65 03 63 6F 6D }
        
        // USER-AGENT: Google Chrome/60.0.3112.90 Windows
        $b4 = { 55 53 45 52 2D 41 47 45 4E 54 3A 20 47 6F 6F 67 6C 65 20 43 68 72 6F 6D 65 2F 36 30 2E 30 2E 33 31 31 32 2E 39 30 20 57 69 6E 64 6F 77 73}
        
        // algorithm="MD5"
        $b5 = { 61 6C 67 6F 72 69 74 68 6D 3D 22 4D 44 35 22 }
        
        // <NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>
        $b6 = { 3C 4E 65 77 44 6F 77 6E 6C 6F 61 64 55 52 4C 3E 24 28 65 63 68 6F 20 48 55 41 57 45 49 55 50 4E 50 29 3C 2F 4E 65 77 44 6F 77 6E 6C 6F 61 64 55 52 4C 3E }

        // wget -g 185.117.119.71
        $ip1 = { 77 67 65 74 20 2D 67 20 31 38 35 2E 31 31 37 2E 31 31 39 2E 37 31 }

    condition : 
        ( $header at 0 ) 
        and 3 of ( $b* )
        and ( $ip1 or true ) 
        and filesize < 1000KB
}

rule Linux_gafgyt_trojan_1ea3d { 
    meta : 
		creation_date = "28/12/2024"
        fingerprint = "dbed61f623d0f915bc0841a016c606423661514b92d1bc797533415690ddbfaa"
        github = "https://github.com/Zaque-69"
        os = "Linux"

    strings : 
        $header = { 7F 45 4C 46 }
        
        // /x38/xFJ/x93/xID/x9A
        $b1 = { 2F 78 33 38 2F 78 46 4A 2F 78 39 33 2F 78 49 44 2F 78 39 41 }

    condition : 
        all of them
        and filesize < 1000KB
}