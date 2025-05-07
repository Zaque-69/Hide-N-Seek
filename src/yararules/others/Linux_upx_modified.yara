// "UPX modified" are viruses that do not decompress and have been modified in their structure.

rule Linux_upx_modiified_304d0957 {
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "36EFC7318C87E2DAB13AD3CDD78759B51628C0765905BEACD8E7A2F8496F32A0"
        sample = "https://bazaar.abuse.ch/download/304d0957dba6fa736744eb0da5530d9056415ef0ce5d103d7bba8eefe1b6ac4e/"
        os = "Linux"

    strings : 
        
        // N...UPX!
        $b1 = { 4E F5 99 DA 55 50 58 21 }

        // d..ELF
        $b2 = { 64 F9 7F 45 4C 46 }

        // ]GaH9Ta9
        $b3 = { 5D 47 61 48 39 54 61 39 }

    condition : 
        filesize > 10KB
        and filesize < 30KB
        and all of them
}

rule Linux_upx_modiified_90afe3be {
    meta : 
		creation_date = "06/05/2025"
        github = "https://github.com/Zaque-69"
        fingerprint = "F3C7171C2E33D45B52ED55E985193A1F7A33E68A4FCA492548E9160B356DE7A1"
        sample = "https://bazaar.abuse.ch/download/90afe3be00cc6cc67a460ff5e50a5dc86f796350df367cd6732c3c19448a6dd5/"
        os = "Linux"

    strings : 
        
        // H.UPX!
        $b1 = { 48 C5 55 50 58 21 }

        // w....ELF
        $b2 = { 77 1F A4 F9 7F 45 4C 46 }

        // keep-alive.Ac
        $b3 = { 6B 65 65 70 2D 61 6C 69 76 65 2E 41 63 }

        // Huawei
        $b4 = { 48 75 61 77 65 69 }

    condition : 
        filesize > 10KB
        and filesize < 30KB
        and all of them
}
